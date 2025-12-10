from machine import Pin, I2C
import rp2
import utime
import sys
import os


##### Constants #####

# Pins
SDA_PIN = 0
SCL_PIN = 1
BTN_PIN = 16
LED_PIN = 25

# I2C addresses
I2C_CMD_ADDR = 0x5A
I2C_DATA_ADDR = 0x35
I2C_BLOCK_ADDR = 0x79

# I2C frequency
I2C_FREQ = 400_000

# Chip ID register value
CHIP_ID = 0x8380

# Embedded flash page size
PAGE_SIZE = (1 << 8)

# Embedded flash block write size for different programming modes
BLOCK_WRITE_SIZE = (1 << 16)

# The amount of flash that should be read into RAM at once (set it well within the device's RAM capacity)
# Note: Must be multiple of PAGE_SIZE
CHUNK_SIZE = PAGE_SIZE * 8

# JEDEC SPI Flash commands
SPI_CMD_PAGE_PROGRAM = 0x02
SPI_CMD_WRITE_DISABLE = 0x04
SPI_CMD_READ_STATUS = 0x05
SPI_CMD_WRITE_ENABLE = 0x06
SPI_CMD_FAST_READ = 0x0B
SPI_CMD_CHIP_ERASE = 0x60
SPI_CMD_SECTOR_ERASE_1K = 0xD7
SPI_CMD_SECTOR_ERASE_4K = 0x20
SPI_CMD_WORD_PROGRAM = 0xAD
SPI_CMD_EWSR = 0x50 # Enable Write Status Register
SPI_CMD_WRSR = 0x01 # Write Status Register
SPI_CMD_RDID = 0x9F # Read Flash ID

# Eflash Type
EFLASH_TYPE_8315 = 0x01
EFLASH_TYPE_KGD = 0x02
EFLASH_TYPE_NONE = 0xFF


##### Configuration #####

# Config (set it here)
send_waveform = True
disable_watchdog = True
disable_protect_path = True
verify = True
wdt_enable = False

# Config (gets set by check_chipid)
flash_cmd_v2 = False
dbgr_addr_3bytes = False
instruction_set_v2 = False
it5xxxx = False
flash_size = 0

# Config (gets set by other functions)
eflash_type = 0
spi_cmd_sector_erase = 0
sector_erase_pages = 0 # Embedded flash number of pages in a sector erase


##### Button and LED #####

button = Pin(BTN_PIN, Pin.IN)
led = Pin(LED_PIN, Pin.OUT)
led.value(0)

button_pressed = False

# Turn on the LED for the given amount of time before turning it back off
def blink_led(blink_length):
    led.value(1)
    utime.sleep(blink_length)
    led.value(0)

# LED blink to indicate success (one long flash)
def blink_led_success():
    blink_led(1)
    utime.sleep(1)

# LED blink to indicate failure (two short flashes)
def blink_led_failure():
    blink_led(0.1)
    utime.sleep(0.1)
    blink_led(0.1)
    utime.sleep(1)

# LED blink to indicate microcontroller reset (four short flashes)
def blink_led_reset():
    blink_led(0.1)
    utime.sleep(0.1)
    blink_led(0.1)
    utime.sleep(0.1)
    blink_led(0.1)
    utime.sleep(0.1)
    blink_led(0.1)
    utime.sleep(1)


##### Logging #####

# Create an empty log file (clears any existing log file)
def clear_log():
    f = open("log.txt", "w")
    f.close()

# Print and write string to log file
def log(string):
    print(string)
    with open("log.txt", "a") as f:
        f.write(string + "\n")

# Log error message, optionally log an exception, then either reset the microcontroller or exit
def error(string, exception=None, reset=False):
    log("ERROR: " + string)
    
    if exception:
        log("=> " + str(exception))
    
    if reset:
        blink_led_reset()
        machine.reset()
    else:
        blink_led_failure()
        sys.exit()


##### Start #####

# Wait for button press
while not button_pressed:
    if button.value():
        button_pressed = True

# Blink LED for success to signal start
blink_led_success()

clear_log()


##### Bitbang Waveform #####

# Define PIO program for sending bitbang waveform
# Note: Program can only have 32 instructions max
# set(pins, 0) -> SDA low,  SCL low
# set(pins, 1) -> SDA high, SCL low
# set(pins, 2) -> SDA low,  SCL high
# set(pins, 3) -> SDA high, SCL high
# [x] -> delay for x cycles (don't forget that each instruction takes one cycle, e.g. so [1] after an instruction means 2 cycle delay in total before next instruction)
@rp2.asm_pio(set_init=(rp2.PIO.OUT_LOW, rp2.PIO.OUT_LOW)) # The set_init specifies two pins that both start with low output (since base pin is set to pin 0, the second pin is pin 1)
def waveform_pio():
    # Put loop iteration number sent with sm.put(...) into x register
    pull()
    mov(x, osr)
    
    # Loop 2000 times, each time sending 10us of waveform pattern (8 * 1.25us bitbang values)
    label("loop")
    set(pins, 1) [1]
    set(pins, 3) [1]
    set(pins, 2) [1]
    set(pins, 2) [1]
    set(pins, 3) [1]
    set(pins, 1) [1]
    set(pins, 0) [1]
    set(pins, 0) # Following jmp instruction adds 1 cycle delay before next set, so don't need any delay here
    jmp(x_dec, "loop") # Decrement x and loop until x is 0
    
    # Signal end of waveform to the script by sending interrupt (this triggers the interrupt handler)
    irq(block, 0)
    
    # Infinite loop at end of program to ensure instructions at beginning don't execute before script can turn off the state machine
    # Note: This is needed because PIO programs loop back to the start when they reach the end, which we don't want here, so this loop prevents that
    label("halt")
    jmp("halt")

# Create PIO state machine
# Note: Frequency of 400 KHz gives cycle time of 2.5us
# Note: Frequency of 800 KHz gives cycle time of 1.25us, meaning an instruction with [1] after gives total time of 2.5us
# Note: Frequency of 1.6 MHz gives cycle time of 0.625us, meaning an instruction with [1] after gives total time of 1.25us
sm = rp2.StateMachine(0, waveform_pio, freq=1_600_000, set_base=Pin(SDA_PIN))

waveform_complete = False

# Define interrupt handler that signals end of waveform by setting a boolean
def irq_handler(sm):
    global waveform_complete
    waveform_complete = True

# Set the interrupt handler
sm.irq(handler=irq_handler)

def send_special_waveform():
    global waveform_complete
    
    waveform_complete = False

    start_us = utime.ticks_us()

    # Turn on PIO state machine (i.e. start sending bitbang waveform)
    sm.active(1)

    # Set the number of iterations for the waveform signal
    # Note: This has to be passed to the state machine from here and not put as an immediate value in the PIO code because the set instruction can only take values from 0-31
    num_iter = 2000
    sm.put(num_iter - 1)

    # Wait for state machine to finish executing
    while not waveform_complete:
        pass

    # Log total time taken to send waveform
    end_us = utime.ticks_us()
    elapsed_us = utime.ticks_diff(end_us, start_us)
    log(f"Waveform duration: {elapsed_us} us")

    # Turn off PIO state machine
    sm.active(0)

send_special_waveform()

# Wait 10ms for EC chip to be ready before proceeding with I2C communication
utime.sleep_ms(10)


##### I2C Scan #####

i2c = I2C(0, scl=Pin(SCL_PIN), sda=Pin(SDA_PIN), freq=I2C_FREQ)

# Perform I2C scan and return true if EC address found, false otherwise
def check_ec_responding():
    ec_responding = False
    
    devices = i2c.scan()
        
    if devices:
        cmd_address_found = False
        data_address_found = False
        
        for device in devices:
            log(hex(device))
            if (device == I2C_CMD_ADDR): # Check if it is EC cmd address
                cmd_address_found = True
            elif (device == I2C_DATA_ADDR): # Check if it is EC data address
                data_address_found = True
        
        if cmd_address_found and data_address_found:
            ec_responding = True
    else:
        log("No devices found!")
    
    return ec_responding

ec_responding = check_ec_responding()

# If no EC response, reset the microcontroller to try again
if (not ec_responding):
    error("No response from EC!", reset=True)

log("EC is responding!\n")
blink_led_success()


##### I2C Communication #####

# Write command to then write byte from EC chip
def i2c_write_byte(cmd, data):
    i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))
    i2c.writeto(I2C_DATA_ADDR, bytes([data]))

# Write command to then read byte from EC chip
def i2c_read_byte(cmd):
    i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))
    data = i2c.readfrom(I2C_DATA_ADDR, 1)[0]
    return data


# Restart watchdog
def restart_wdt():
    if dbgr_addr_3bytes:
        i2c_write_byte(0x80, 0xf0)
    i2c_write_byte(0x2f, 0x1f)
    i2c_write_byte(0x2e, (0x87 if instruction_set_v2 else 0x07))
    i2c_write_byte(0x30, 0x5C)

# Check if need wdt restart
def check_wdt():
    if wdt_enable:
        restart_wdt()

def spi_flash_follow_mode():
    check_wdt()
    
    i2c_write_byte(0x07, 0x7f)
    i2c_write_byte(0x06, 0xff)
    i2c_write_byte(0x05, 0xfe)
    i2c_write_byte(0x04, 0x00)
    i2c_write_byte(0x08, 0x00)

def spi_flash_follow_mode_exit():
    i2c_write_byte(0x07, 0x00)
    i2c_write_byte(0x06, 0x00)

def dbgr_stop_ec():
    spi_flash_follow_mode()
    spi_flash_follow_mode_exit()

try:
    # Stop EC ASAP after sending special waveform
    dbgr_stop_ec()
except Exception as e:
    error("dbgr_stop_ec failed!", e)

log("dbgr_stop_ec completed!\n")
blink_led_success()


def get_3rd_chip_id_byte():
    i2c_write_byte(0x80, 0xf0)
    i2c_write_byte(0x2f, 0x20)
    i2c_write_byte(0x2e, 0x85)
    chip_id = i2c_read_byte(0x30)
    return chip_id

def it5xxxx_get_eflash_size():
    i2c_write_byte(0x80, 0xf0)
    i2c_write_byte(0x2f, 0x10)
    i2c_write_byte(0x2e, 0x80)
    eflash_size = i2c_read_byte(0x30)
    return eflash_size

# Fetches and prints chip ID, version and flash size, and also sets various options based on this info to be used later
def check_chipid():
    global flash_cmd_v2, dbgr_addr_3bytes, instruction_set_v2, it5xxxx, flash_size
    
    eflash_size = 0xff
    v2 = [128, 192, 256, 384, 512, 0, 1024]
    
    it5xxxx = False
    
    # Read ID from chip
    id_byte_upper = i2c_read_byte(0x00)
    id_byte_lower = i2c_read_byte(0x01)
    id_ = (id_byte_upper << 8) | id_byte_lower
    
    # Read version from chip
    ver = i2c_read_byte(0x02)
    
    # Set various options based on chip ID and version
    if False and ((id_ & 0xff00) != (CHIP_ID & 0xff00)): # False is added here to force this condition to not be true since it is broken
        id_ |= 0xff0000
        id_third_byte = get_3rd_chip_id_byte()
        id_ = (id_third_byte << 16) | id_
        
        if ((id_ & 0xf000f) == 0x80001) or ((id_ & 0xf000f) == 0x80002):
            flash_cmd_v2 = True
            dbgr_addr_3bytes = True
            if (id_ & 0xf00f) == 0x2002:
                instruction_set_v2 = True
        elif (id_ & 0xf0000) == 0x50000:
            # Reset and halt CPU
            i2c_write_byte(0x27, 0x81)
            
            it5xxxx = True
            flash_cmd_v2 = True
            dbgr_addr_3bytes = True
            eflash_size = it5xxxx_get_eflash_size()
        else:
            raise Exception(f"Invalid chip id: {id_:05x}")
    else:
        dbgr_addr_3bytes = False
        if (ver & 0x0f) >= 0x03:
            flash_cmd_v2 = True
        else:
            flash_cmd_v2 = False
    
    # Compute embedded flash size from CHIPVER field
    if it5xxxx:
        if eflash_size == 0x01:
            flash_size = 128 * 1024
        elif eflash_size == 0x02:
            flash_size = 256 * 1024
        elif eflash_size == 0x0E:
            flash_size = 512 * 1024
        elif eflash_size == 0x0F:
            flash_size = 1024 * 1024
    elif flash_cmd_v2:
        flash_size = v2[(ver & 0xF0) >> 5] * 1024
    else:
        flash_size = (128 + (ver & 0xF0)) * 1024
    
    if flash_size == 0:
        raise Exception("Invalid flash size")
    
    log(f"CHIPID {id_:05x}, CHIPVER {ver:02x}, Flash size {flash_size / 1024} kB")

try:
    check_chipid()
except Exception as e:
    error("Failed to get chip ID!", e)

log("Successfully fetched chip ID!\n")
blink_led_success()


# TODO: Fix the freeze
# Reset GPIOs to default
def dbgr_reset_gpio():
    log("Inside dbgr_reset_gpio...")
    if dbgr_addr_3bytes:
        i2c_write_byte(0x80, 0xf0)
    log("1...")
    i2c_write_byte(0x2f, 0x20)
    log("2...")
    i2c_write_byte(0x2e, 0x07)
    log("3...")
    i2c_write_byte(0x30, 0x02) # This line freezes when done after previous lines in this function
    log("Reached end of dbgr_reset_gpio!")

# TODO: Fix dbgr_reset_gpio and uncomment the below if experiencing issues with later functions
# Note: This is commented out since dbgr_reset_gpio freezes

# try:
#     # Turn off power rails by reset GPIOs to default (input)
#     dbgr_reset_gpio()
# except Exception as e:
#     error("dbgr_reset_gpio failed!")
# 
# log("dbgr_reset_gpio completed!\n")
# blink_led_success()


# Fetches and prints flash ID, and sets the eflash type
def check_flashid():
    global eflash_type
    
    i2c_write_byte(0x07, 0x7f)
    i2c_write_byte(0x06, 0xff)
    i2c_write_byte(0x04, 0x00)
    i2c_write_byte(0x05, 0xfe)
    i2c_write_byte(0x08, 0x00)
    i2c_write_byte(0x05, 0xfd)
    i2c_write_byte(0x08, 0x9f)
    
    id_ = i2c.readfrom(I2C_DATA_ADDR, 16)
    
    if id_[0] == 0xff and id_[1] == 0xff and id_[2] == 0xfe:
        log("EFLASH TYPE = 8315")
        eflash_type = EFLASH_TYPE_8315
    elif id_[0] == 0xc8 or id_[0] == 0xef:
        log("EFLASH TYPE = KGD")
        eflash_type = EFLASH_TYPE_KGD
    else:
        eflash_type = EFLASH_TYPE_NONE
        raise Exception(f"Invalid EFLASH TYPE: FLASH ID = {id_[0]:02x} {id_[1]:02x} {id_[2]:02x}")

try:
    check_flashid()
except Exception as e:
    error("Failed to get flash ID!", e)

log("Successfully fetched flash ID!\n")
blink_led_success()


try:
    # Add wdt restart to prevent wdt interrupt flashing
    restart_wdt()
except Exception as e:
    error("Failed to restart wdt!", e)

log("Restart wdt completed!\n")
blink_led_success()


# Get watchdog
def get_wdt_value():
    if dbgr_addr_3bytes:
        i2c_write_byte(0x80, 0xf0)
    i2c_write_byte(0x2f, 0x1f)
    i2c_write_byte(0x2e, 0x85 if instruction_set_v2 else 0x05)
    watchdog = i2c_read_byte(0x30)
    return watchdog

# Set watchdog
def set_wdt_value(watchdog):
    if dbgr_addr_3bytes:
        i2c_write_byte(0x80, 0xf0)
    i2c_write_byte(0x2f, 0x1f)
    i2c_write_byte(0x2e, 0x85 if instruction_set_v2 else 0x05)
    i2c_write_byte(0x30, watchdog)

# Disable watchdog
def dbgr_disable_watchdog():
    global wdt_enable
    
    log("Disabling watchdog...")
    
    restart_wdt()
    
    set_wdt_value(0x10)
    utime.sleep_ms(1)
    
    set_wdt_value(0x30)
    utime.sleep_ms(1)
    
    wdt = get_wdt_value()
    
    if wdt != 0x30:
        log("DBGR DISABLE WATCHDOG FAILED!")
        log(f"wdt={wdt:02x} => do restart wdt to avoid wdt interrupt flashing...")
        wdt_enable = True
        restart_wdt()

# Disable protect path from DBGR
def dbgr_disable_protect_path():
    log("Disabling protect path...")
    
    if dbgr_addr_3bytes:
        i2c_write_byte(0x80, 0xf0)
    
    i2c_write_byte(0x2f, 0x20)
    
    for i in range(32):
        i2c_write_byte(0x2e, 0xa0 + i)
        i2c_write_byte(0x30, 0)

def post_waveform_work():
    if disable_watchdog:
        dbgr_disable_watchdog()
    
    if disable_protect_path:
        dbgr_disable_protect_path()

try:
    post_waveform_work()
except Exception as e:
    error("Failed to do post waveform work!", e)

log("Post waveform work completed!\n")
blink_led_success()


##### Read and Verify Flash #####

# SPI Flash generic command, short version
def spi_flash_command_short(cmd):
    i2c_write_byte(0x05, 0xfe)
    i2c_write_byte(0x08, 0x00)
    i2c_write_byte(0x05, 0xfd)
    i2c_write_byte(0x08, cmd)

# Note: This function must be called in follow mode
def spi_send_cmd_fast_read(addr):
    cmd = 0x9
    
    # Check if need wdt restart
    check_wdt()
    
    # Fast Read command
    spi_flash_command_short(SPI_CMD_FAST_READ)
    
    # Send address
    i2c_write_byte(0x08, ((addr >> 16) & 0xff)) # addr_h
    i2c_write_byte(0x08, ((addr >> 8) & 0xff))  # addr_m
    i2c_write_byte(0x08, (addr & 0xff))         # addr_l
    
    # Fake byte
    i2c_write_byte(0x08, 0x00)
    
    # Use i2c block read command
    i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))

# Read pages of flash memory from address to address+size and return a buffer containing the data read
def command_read_pages(address, size):
    # We need to resend fast read command at 256KB boundary
    # If wdt_enable, we need to reduce to 4KB to avoid the wdt interrupt
    boundary = 0x40000 # 256K
    if wdt_enable:
        boundary = 0x1000 # 4K
    
    if address & 0xFF:
        raise Exception(f"Page read requested at non-page boundary: {hex(address)}")
    
    spi_flash_follow_mode()
    
    spi_send_cmd_fast_read(address)
    
    remaining = size
    offset = 0
    buffer = bytearray(size)
    
    while remaining:
        count = min(PAGE_SIZE, remaining)
        
        # Read page data
        data = i2c.readfrom(I2C_BLOCK_ADDR, count)
        buffer[offset:offset + count] = data
        
        address += count
        remaining -= count
        offset += count
        
        # We need to resend fast read command at boundary
        if (address % boundary == 0) and remaining:
            spi_send_cmd_fast_read(address)
    
    spi_flash_follow_mode_exit()
    
    return buffer

# Note: Due to the pico's 264kB of RAM, we can't just load up a copy of the firmware into memory since we may run out of space, hence the chunking
def read_flash(filename):
    remaining = flash_size
    offset = 0
    
    with open(filename, "wb") as f:
        while remaining:
            count = min(CHUNK_SIZE, remaining)
            
            flash_chunk = command_read_pages(offset, count)
            f.write(flash_chunk)
            
            remaining -= count
            offset += count
    
    log(f"{flash_size / 1024} kB read")

# Read flash contents and compare it with contents of given file, and raise exception if content doesn't match
# Note: Due to the pico's 264kB of RAM, we can't just load up two copies of the firmware into memory since we'll run out of space, hence the chunking
def verify_flash(filename):
    remaining = flash_size
    offset = 0
    
    with open(filename, "rb") as f:
        while remaining:
            count = min(CHUNK_SIZE, remaining)
            
            flash_chunk = command_read_pages(offset, count)
            file_chunk = f.read(count)
            
            for i in range(count):
                if flash_chunk[i] != file_chunk[i]:
                    raise Exception(f"Flash and file differ at {hex(offset + i)}")
            
            remaining -= count
            offset += count
    
    log("Flash and file match!")


# try:
#     read_flash("dump.bin")
# except Exception as e:
#     error("Failed to read flash!", e)
# 
# log("Successfully read flash!\n")
# blink_led_success()
# 
# 
# try:
#     verify_flash("dump.bin")
# except Exception as e:
#     error("Failed to verify flash!", e)
# 
# log("Successfully verified flash!\n")
# blink_led_success()


##### Erase Flash #####

def spi_flash_set_erase_page(page):
    i2c_write_byte(0x08, page >> 8)
    i2c_write_byte(0x08, page & 0xff)
    i2c_write_byte(0x08, 0)

# Poll SPI Flash Read Status register until BUSY is reset
def spi_poll_busy():
    spi_flash_command_short(SPI_CMD_READ_STATUS)
    
    while True:
        reg = i2c.readfrom(I2C_DATA_ADDR, 1)[0]
        
        if (reg & 0x01) == 0:
            # Busy bit cleared
            break

def spi_check_write_enable():
    spi_flash_command_short(SPI_CMD_READ_STATUS)
    
    while True:
        reg = i2c.readfrom(I2C_DATA_ADDR, 1)[0]
        
        if (reg & 0x03) == 2:
            # Busy bit cleared and WE bit set
            break

# Erase entire chip
def command_erase():
    log("Erasing chip...")
    
    spi_flash_follow_mode()
    spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
    spi_check_write_enable()
    
    # Do chip erase
    spi_flash_command_short(SPI_CMD_CHIP_ERASE)
    
    spi_poll_busy()
    spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
    spi_flash_follow_mode_exit()
    
    log("Erasing done!")

def command_erase2():
    log("Erasing chip...")
    
    page = 0
    remaining = flash_size
    
    spi_flash_follow_mode()
    
    while remaining:
        spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
        spi_check_write_enable()
        
        # Do sector erase
        spi_flash_command_short(spi_cmd_sector_erase)
        spi_flash_set_erase_page(page)
        
        spi_poll_busy()
        spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        
        # Check if need wdt restart
        check_wdt()
        
        page += sector_erase_pages
        remaining -= sector_erase_pages * PAGE_SIZE
    
    spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
    spi_flash_follow_mode_exit()
    
    log("Erasing done!")

def erase_flash():
    if flash_cmd_v2:
        command_erase2()
    else:
        command_erase()

# Read flash contents and check if each byte is 0xFF, and raise exception if any byte isn't
# Note: Due to the pico's 264kB of RAM, we can't just load up a copy of the firmware into memory since we may run out of space, hence the chunking
def verify_flash_empty():
    remaining = flash_size
    offset = 0
    
    while remaining:
        count = min(CHUNK_SIZE, remaining)
        
        flash_chunk = command_read_pages(offset, count)
        
        for i, byte in enumerate(flash_chunk):
            if byte != 0xFF:
                raise Exception(f"Flash not empty: contains byte {hex(byte)} at {hex(i)}")
        
        remaining -= count
        offset += count
    
    log("Flash is empty!")


if eflash_type == EFLASH_TYPE_8315:
    sector_erase_pages = 4
    spi_cmd_sector_erase = SPI_CMD_SECTOR_ERASE_1K
elif eflash_type == EFLASH_TYPE_KGD:
    sector_erase_pages = 16
    spi_cmd_sector_erase = SPI_CMD_SECTOR_ERASE_4K
else:
    error("Invalid EFLASH TYPE!")


# try:
#     erase_flash()
# except Exception as e:
#     error("Failed to erase flash!", e)
# 
# log("Successfully erased flash!\n")
# blink_led_success()
# 
# 
# try:
#     verify_flash_empty()
# except Exception as e:
#     error("Failed to verify empty flash!", e)
# 
# log("Successfully verified empty flash!\n")
# blink_led_success()


##### Write Flash #####

# Write to pages of flash memory from address to address+size from a buffer containing the data write
def command_write_pages(address, size, buffer):
    block_write_size = BLOCK_WRITE_SIZE
    remaining = size
    offset = 0
    
    spi_flash_follow_mode()
    
    while remaining:
        count = min(block_write_size, remaining)
        
        addr_H = (address >> 16) & 0xFF
        addr_M = (address >> 8) & 0xFF
        addr_L = address & 0xFF
        
        # Write enable
        spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
        
        # Check write enable bit
        spi_check_write_enable()
        
        # Setup write
        spi_flash_command_short(SPI_CMD_WORD_PROGRAM)
        
        # Set eflash page address
        i2c.writeto(I2C_DATA_ADDR, bytes([addr_H]))
        i2c.writeto(I2C_DATA_ADDR, bytes([addr_M]))
        i2c.writeto(I2C_DATA_ADDR, bytes([addr_L]))
        
        # Wait until not busy
        spi_poll_busy()
        
        # Write up to BLOCK_WRITE_SIZE data
        data = buffer[offset:offset + count]
        i2c_write_byte(0x10, 0x20)
        i2c.writeto(I2C_BLOCK_ADDR, data)
        
        i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
        i2c_write_byte(0x10, 0x00)
        
        # Write disable
        spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        
        # Wait until available
        spi_poll_busy()
        
        address += count
        remaining -= count
        offset += count
    
    # Check if need wdt restart
    check_wdt()
    
    spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
    spi_flash_follow_mode_exit()

def write_flash1(filename):
    log(f"Writing {flash_size} bytes...")
    
    remaining = flash_size
    offset = 0
    
    with open(filename, "rb") as f:
        while remaining:
            count = min(CHUNK_SIZE, remaining)
            
            file_chunk = f.read(count)
            
            command_write_pages(offset, count, file_chunk)
            
            remaining -= count
            offset += count
    
    log("Writing done!")

def write_flash2(filename):
    log(f"Writing {flash_size} bytes...")
    
    log("In write_flash2...")
    
    block_write_size = BLOCK_WRITE_SIZE
    size = flash_size
    
    # We need to resend fast read command at 256KB boundary
    # If wdt_enable, we need to reduce to 4KB to avoid the wdt interrupt
    boundary = 0x40000 # 256K
    if wdt_enable:
        boundary = 0x1000 # 4K
    
    spi_flash_follow_mode()
    
    offset = 0
    remaining = size
    two_bytes_sent = False
    
    with open(filename, "rb") as f:
        def send_aai_cmd():
            nonlocal offset, remaining, two_bytes_sent
            
            addr_h = (offset >> 16) & 0xff
            addr_m = (offset >> 8) & 0xff
            addr_l = offset & 0xff
            
            # Check if need wdt restart
            check_wdt()
            
            # Write enable command
            spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
            
            # AAI command
            spi_flash_command_short(SPI_CMD_WORD_PROGRAM)
            
            # Address of AAI command
            i2c.writeto(I2C_DATA_ADDR, bytes([addr_h]))
            i2c.writeto(I2C_DATA_ADDR, bytes([addr_m]))
            i2c.writeto(I2C_DATA_ADDR, bytes([addr_l]))
            
            # Send first two bytes of buffer
            i2c.writeto(I2C_DATA_ADDR, bytes(f.read(1)))
            i2c.writeto(I2C_DATA_ADDR, bytes(f.read(1)))
            
            log(f"Wrote 2 bytes at offset {offset}")
            
            # We had sent two bytes
            offset += 2
            remaining -= 2
            two_bytes_sent = True
            
            # Wait until not busy
            spi_poll_busy()
            
            # Enable quick AAI mode
            i2c_write_byte(0x10, 0x20)
        
        log("Sending AAI cmd...")
        send_aai_cmd()
        
        while remaining:
            count = min(block_write_size, remaining)
            
            # We had sent two bytes
            if two_bytes_sent:
                two_bytes_sent = False
                count -= 2
            
            data = f.read(count)
            i2c.writeto(I2C_BLOCK_ADDR, data)
            
            log(f"Wrote {count} bytes at offset {offset}")
            
            remaining -= count
            offset += count
            
            # We need to resend AAI write command at boundary
            if (offset % boundary == 0) and remaining:
                log("Resending AAI write command...")
                
                # Disable quick AAI mode
                i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
                i2c_write_byte(0x10, 0x00)
                
                # Write disable command
                spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
                
                send_aai_cmd()
                
                log("Resent AAI write command")
    
    # Disable quick AAI mode
    i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
    i2c_write_byte(0x10, 0x00)
    
    # Write disable command
    spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
    
    # Exit follow mode
    spi_flash_follow_mode_exit()
    
    log("Writing done!")

def write_flash3(filename):
    # TODO
    pass

def write_flash(filename):
    if flash_cmd_v2:
        if eflash_type == EFLASH_TYPE_8315:
            write_flash2(filename)
        elif eflash_type == EFLASH_TYPE_KGD:
            write_flash3(filename)
        else:
            raise Exception("Invalid EFLASH TYPE!")
    else:
        write_flash1(filename)


try:
    write_flash("ec.bin")
except Exception as e:
    error("Failed to write flash!", e)

log("Successfully written flash!\n")
blink_led_success()


try:
    verify_flash("ec.bin")
except Exception as e:
    error("Failed to verify flash!", e)

log("Successfully verified flash!\n")
blink_led_success()


##### Finish #####

# Endlessly blink the LED to signify the end of the script
while True:
    blink_led(0.3)
    utime.sleep(0.3)
