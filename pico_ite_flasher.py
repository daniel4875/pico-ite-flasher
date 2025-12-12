from machine import Pin, I2C
import rp2
import utime
import sys


##### Configuration #####

class Mode:
    READ = 0
    ERASE = 1
    WRITE = 2

mode = Mode.READ

firmware_file = "ec.bin"
log_file = "log.txt"

# Pins
sda_pin = 0
scl_pin = 1
btn_pin = 16
led_pin = 25

# I2C frequency
i2c_freq = 400_000

send_waveform = True
verify = True
disable_watchdog = True
disable_protect_path = True


##### Constants #####

# I2C addresses
I2C_CMD_ADDR = 0x5A
I2C_DATA_ADDR = 0x35
I2C_BLOCK_ADDR = 0x79

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


##### Button and LED #####

button = Pin(btn_pin, Pin.IN)
led = Pin(led_pin, Pin.OUT)
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
    f = open(log_file, "w")
    f.close()

# Print and write string to log file
def log(string):
    print(string)
    with open(log_file, "a") as f:
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


##### Flashing #####

class ITEFlasher:

    def __init__(self, sda_pin, scl_pin, i2c_freq=400_000, send_waveform=True, verify=True, disable_watchdog=True, disable_protect_path=True):
        # Create PIO state machine
        # Note: Frequency of 400 KHz gives cycle time of 2.5us
        # Note: Frequency of 800 KHz gives cycle time of 1.25us, meaning an instruction with [1] after gives total time of 2.5us
        # Note: Frequency of 1.6 MHz gives cycle time of 0.625us, meaning an instruction with [1] after gives total time of 1.25us
        self._sm = rp2.StateMachine(0, ITEFlasher._waveform_pio_program, freq=1_600_000, set_base=Pin(sda_pin))

        # Set the interrupt handler that signals end of waveform by setting a boolean
        self._sm.irq(handler=lambda sm: self._complete_waveform())

        self._i2c = I2C(0, scl=Pin(scl_pin), sda=Pin(sda_pin), freq=i2c_freq)

        # Flags set by other methods
        self.waveform_complete = False
        self.wdt_enabled = False

        # Config
        self.send_waveform = send_waveform
        self.verify = verify
        self.disable_watchdog = disable_watchdog
        self.disable_protect_path = disable_protect_path

        # Config (set by check_chipid)
        self.flash_cmd_v2 = False
        self.dbgr_addr_3bytes = False
        self.instruction_set_v2 = False
        self.it5xxxx = False
        self.flash_size = 0

        # Config (set by check_flashid)
        self.eflash_type = 0
        self.spi_cmd_sector_erase = 0
        self.sector_erase_pages = 0 # Embedded flash number of pages in a sector erase
    

    def connect(self):
        if self.send_waveform:
            self.send_special_waveform()

            # Wait 10ms for EC chip to be ready before proceeding with I2C communication
            utime.sleep_ms(10)

        ec_responding = self.check_ec_responding()

        # If no EC response, reset the microcontroller to try again
        if (not ec_responding):
            error("No response from EC!", reset=True)

        log("EC is responding!\n")
        blink_led_success()

        try:
            # Stop EC ASAP after sending special waveform
            self.dbgr_stop_ec()
        except Exception as e:
            error("dbgr_stop_ec failed!", e)

        log("dbgr_stop_ec completed!\n")
        blink_led_success()

        try:
            self.check_chipid()
        except Exception as e:
            error("Failed to get chip ID!", e)

        log("Successfully fetched chip ID!\n")
        blink_led_success()

        # TODO: Fix dbgr_reset_gpio and uncomment the below if experiencing issues with later functions
        # Note: This is commented out since dbgr_reset_gpio freezes

        # try:
        #     # Turn off power rails by resetting GPIOs to default (input)
        #     self.dbgr_reset_gpio()
        # except Exception as e:
        #     error("dbgr_reset_gpio failed!")
        # 
        # log("dbgr_reset_gpio completed!\n")
        # blink_led_success()

        try:
            self.check_flashid()
        except Exception as e:
            error("Failed to get flash ID!", e)

        log("Successfully fetched flash ID!\n")
        blink_led_success()

        try:
            # Add wdt restart to prevent wdt interrupt flashing
            self.restart_wdt()
        except Exception as e:
            error("Failed to restart wdt!", e)

        log("Restart wdt completed!\n")
        blink_led_success()

        try:
            self.post_waveform_work()
        except Exception as e:
            error("Failed to do post waveform work!", e)

        log("Post waveform work completed!\n")
        blink_led_success()


    ##### Bitbang Waveform #####

    # Define PIO program for sending bitbang waveform
    # Note: Program can only have 32 instructions max
    # set(pins, 0) -> SDA low,  SCL low
    # set(pins, 1) -> SDA high, SCL low
    # set(pins, 2) -> SDA low,  SCL high
    # set(pins, 3) -> SDA high, SCL high
    # [x] -> delay for x cycles (don't forget that each instruction takes one cycle, e.g. so [1] after an instruction means 2 cycle delay in total before next instruction)
    @rp2.asm_pio(set_init=(rp2.PIO.OUT_LOW, rp2.PIO.OUT_LOW)) # The set_init specifies two pins that both start with low output (since base pin is set to pin 0, the second pin is pin 1)
    def _waveform_pio_program():
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

    def _complete_waveform(self):
        self.waveform_complete = True
    
    def send_special_waveform(self):
        self.waveform_complete = False

        start_us = utime.ticks_us()

        # Turn on PIO state machine (i.e. start sending bitbang waveform)
        self._sm.active(1)

        # Set the number of iterations for the waveform signal
        # Note: This has to be passed to the state machine from here and not put as an immediate value in the PIO code because the set instruction can only take values from 0-31
        num_iter = 2000
        self._sm.put(num_iter - 1)

        # Wait for state machine to finish executing
        while not self.waveform_complete:
            pass

        # Log total time taken to send waveform
        end_us = utime.ticks_us()
        elapsed_us = utime.ticks_diff(end_us, start_us)
        log(f"Waveform duration: {elapsed_us} us")

        # Turn off PIO state machine
        self._sm.active(0)
    

    ##### I2C Scan #####
    
    # Perform I2C scan and return true if EC address found, false otherwise
    def check_ec_responding(self):
        ec_responding = False
        
        devices = self._i2c.scan()
            
        if devices:
            cmd_address_found = False
            data_address_found = False
            
            for device in devices:
                log(hex(device))
                if (device == I2C_CMD_ADDR): # Check if EC cmd address
                    cmd_address_found = True
                elif (device == I2C_DATA_ADDR): # Check if EC data address
                    data_address_found = True
            
            if cmd_address_found and data_address_found:
                ec_responding = True
        else:
            log("No devices found!")
        
        return ec_responding
    

    ##### I2C Communication #####

    # Write command to then write byte to EC chip
    def _i2c_write_byte(self, cmd, data):
        self._i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))
        self._i2c.writeto(I2C_DATA_ADDR, bytes([data]))

    # Write command to then read byte from EC chip
    def _i2c_read_byte(self, cmd):
        self._i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))
        data = self._i2c.readfrom(I2C_DATA_ADDR, 1)[0]
        return data

    # Restart watchdog
    def restart_wdt(self):
        if self.dbgr_addr_3bytes:
            self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x1f)
        self._i2c_write_byte(0x2e, (0x87 if self.instruction_set_v2 else 0x07))
        self._i2c_write_byte(0x30, 0x5C)

    # Check if need wdt restart
    def check_wdt(self):
        if self.wdt_enabled:
            self.restart_wdt()

    def spi_flash_follow_mode(self):
        self.check_wdt()
        
        self._i2c_write_byte(0x07, 0x7f)
        self._i2c_write_byte(0x06, 0xff)
        self._i2c_write_byte(0x05, 0xfe)
        self._i2c_write_byte(0x04, 0x00)
        self._i2c_write_byte(0x08, 0x00)

    def spi_flash_follow_mode_exit(self):
        self._i2c_write_byte(0x07, 0x00)
        self._i2c_write_byte(0x06, 0x00)

    def dbgr_stop_ec(self):
        self.spi_flash_follow_mode()
        self.spi_flash_follow_mode_exit()
    
    def get_3rd_chip_id_byte(self):
        self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x20)
        self._i2c_write_byte(0x2e, 0x85)
        chip_id = self._i2c_read_byte(0x30)
        return chip_id

    def it5xxxx_get_eflash_size(self):
        self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x10)
        self._i2c_write_byte(0x2e, 0x80)
        eflash_size = self._i2c_read_byte(0x30)
        return eflash_size

    # Fetches and logs chip ID, version and flash size, and also sets various options based on this info to be used later
    def check_chipid(self):
        eflash_size = 0xff
        v2 = [128, 192, 256, 384, 512, 0, 1024]
        
        self.it5xxxx = False
        
        # Read ID from chip
        id_byte_upper = self._i2c_read_byte(0x00)
        id_byte_lower = self._i2c_read_byte(0x01)
        id_ = (id_byte_upper << 8) | id_byte_lower
        
        # Read version from chip
        ver = self._i2c_read_byte(0x02)
        
        # TODO: Fix this since it seems to be broken (false is added for now to force it to not run)
        # Set various options based on chip ID and version
        if False and ((id_ & 0xff00) != (CHIP_ID & 0xff00)):
            id_ |= 0xff0000
            id_third_byte = self.get_3rd_chip_id_byte()
            id_ = (id_third_byte << 16) | id_
            
            if ((id_ & 0xf000f) == 0x80001) or ((id_ & 0xf000f) == 0x80002):
                self.flash_cmd_v2 = True
                self.dbgr_addr_3bytes = True
                if (id_ & 0xf00f) == 0x2002:
                    self.instruction_set_v2 = True
            elif (id_ & 0xf0000) == 0x50000:
                # Reset and halt CPU
                self._i2c_write_byte(0x27, 0x81)
                
                self.it5xxxx = True
                self.flash_cmd_v2 = True
                self.dbgr_addr_3bytes = True
                eflash_size = self.it5xxxx_get_eflash_size()
            else:
                raise Exception(f"Invalid chip id: {id_:05x}")
        else:
            self.dbgr_addr_3bytes = False
            if (ver & 0x0f) >= 0x03:
                self.flash_cmd_v2 = True
            else:
                self.flash_cmd_v2 = False
        
        # Compute embedded flash size from CHIPVER field
        if self.it5xxxx:
            if eflash_size == 0x01:
                self.flash_size = 128 * 1024
            elif eflash_size == 0x02:
                self.flash_size = 256 * 1024
            elif eflash_size == 0x0E:
                self.flash_size = 512 * 1024
            elif eflash_size == 0x0F:
                self.flash_size = 1024 * 1024
        elif self.flash_cmd_v2:
            self.flash_size = v2[(ver & 0xF0) >> 5] * 1024
        else:
            self.flash_size = (128 + (ver & 0xF0)) * 1024
        
        if self.flash_size == 0:
            raise Exception("Invalid flash size")
        
        log(f"CHIPID {id_:05x}, CHIPVER {ver:02x}, Flash size {self.flash_size / 1024} kB")
    
    # TODO: Fix the freeze
    # Reset GPIOs to default
    def dbgr_reset_gpio(self):
        if self.dbgr_addr_3bytes:
            self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x20)
        self._i2c_write_byte(0x2e, 0x07)
        self._i2c_write_byte(0x30, 0x02) # This line freezes when done after previous lines in this function
    
    # Fetches and logs flash ID, and sets the eflash type
    def check_flashid(self):
        self._i2c_write_byte(0x07, 0x7f)
        self._i2c_write_byte(0x06, 0xff)
        self._i2c_write_byte(0x04, 0x00)
        self._i2c_write_byte(0x05, 0xfe)
        self._i2c_write_byte(0x08, 0x00)
        self._i2c_write_byte(0x05, 0xfd)
        self._i2c_write_byte(0x08, 0x9f)
        
        id_ = self._i2c.readfrom(I2C_DATA_ADDR, 16)
        
        if id_[0] == 0xff and id_[1] == 0xff and id_[2] == 0xfe:
            log("EFLASH type = 8315")
            self.eflash_type = EFLASH_TYPE_8315
            self.sector_erase_pages = 4
            self.spi_cmd_sector_erase = SPI_CMD_SECTOR_ERASE_1K
        elif id_[0] == 0xc8 or id_[0] == 0xef:
            log("EFLASH type = KGD")
            self.eflash_type = EFLASH_TYPE_KGD
            self.sector_erase_pages = 16
            self.spi_cmd_sector_erase = SPI_CMD_SECTOR_ERASE_4K
        else:
            raise Exception(f"Invalid EFLASH type: FLASH ID = {id_[0]:02x} {id_[1]:02x} {id_[2]:02x}")
    
    # Get watchdog
    def get_wdt_value(self):
        if self.dbgr_addr_3bytes:
            self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x1f)
        self._i2c_write_byte(0x2e, 0x85 if self.instruction_set_v2 else 0x05)
        watchdog = self._i2c_read_byte(0x30)
        return watchdog

    # Set watchdog
    def set_wdt_value(self, watchdog):
        if self.dbgr_addr_3bytes:
            self._i2c_write_byte(0x80, 0xf0)
        self._i2c_write_byte(0x2f, 0x1f)
        self._i2c_write_byte(0x2e, 0x85 if self.instruction_set_v2 else 0x05)
        self._i2c_write_byte(0x30, watchdog)

    # Disable watchdog
    def dbgr_disable_watchdog(self):
        log("Disabling watchdog...")
        
        self.restart_wdt()
        
        self.set_wdt_value(0x10)
        utime.sleep_ms(1)
        
        self.set_wdt_value(0x30)
        utime.sleep_ms(1)
        
        wdt = self.get_wdt_value()
        
        if wdt != 0x30:
            log("Failed to disable watchdog!")
            log("Restarting wdt to avoid wdt interrupt flashing...")
            self.wdt_enabled = True
            self.restart_wdt()

    # Disable protect path from DBGR
    def dbgr_disable_protect_path(self):
        log("Disabling protect path...")
        
        if self.dbgr_addr_3bytes:
            self._i2c_write_byte(0x80, 0xf0)
        
        self._i2c_write_byte(0x2f, 0x20)
        
        for i in range(32):
            self._i2c_write_byte(0x2e, 0xa0 + i)
            self._i2c_write_byte(0x30, 0)

    def post_waveform_work(self):
        if self.disable_watchdog:
            self.dbgr_disable_watchdog()
        
        if self.disable_protect_path:
            self.dbgr_disable_protect_path()
    

    ##### Read and Verify Flash #####

    # SPI Flash generic command, short version
    def _spi_flash_command_short(self, cmd):
        self._i2c_write_byte(0x05, 0xfe)
        self._i2c_write_byte(0x08, 0x00)
        self._i2c_write_byte(0x05, 0xfd)
        self._i2c_write_byte(0x08, cmd)

    # Note: This function must be called in follow mode
    def _spi_send_cmd_fast_read(self, addr):
        cmd = 0x9
        
        # Check if need wdt restart
        self.check_wdt()
        
        # Fast Read command
        self._spi_flash_command_short(SPI_CMD_FAST_READ)
        
        # Send address
        self._i2c_write_byte(0x08, ((addr >> 16) & 0xff)) # addr_h
        self._i2c_write_byte(0x08, ((addr >> 8) & 0xff))  # addr_m
        self._i2c_write_byte(0x08, (addr & 0xff))         # addr_l
        
        # Fake byte
        self._i2c_write_byte(0x08, 0x00)
        
        # Use i2c block read command
        self._i2c.writeto(I2C_CMD_ADDR, bytes([cmd]))

    # Read pages of flash memory from address to address+size and return a buffer containing the data read
    def _command_read_pages(self, address, size):
        # We need to resend fast read command at 256KB boundary
        # If wdt_enable, we need to reduce to 4KB to avoid the wdt interrupt
        boundary = 0x40000 # 256K
        if self.wdt_enabled:
            boundary = 0x1000 # 4K
        
        if address & 0xFF:
            raise Exception(f"Page read requested at non-page boundary: {hex(address)}")
        
        self.spi_flash_follow_mode()
        
        self._spi_send_cmd_fast_read(address)
        
        remaining = size
        offset = 0
        buffer = bytearray(size)
        
        while remaining:
            count = min(PAGE_SIZE, remaining)
            
            # Read page data
            data = self._i2c.readfrom(I2C_BLOCK_ADDR, count)
            buffer[offset:offset + count] = data
            
            address += count
            remaining -= count
            offset += count
            
            # We need to resend fast read command at boundary
            if (address % boundary == 0) and remaining:
                self._spi_send_cmd_fast_read(address)
        
        self.spi_flash_follow_mode_exit()
        
        return buffer

    # Note: Due to the pico's 264kB of RAM, we can't just load up a copy of the firmware into memory since we may run out of space, hence the chunking
    def read_flash(self, filename):
        log("Reading flash...")

        remaining = self.flash_size
        offset = 0
        
        with open(filename, "wb") as f:
            while remaining:
                count = min(CHUNK_SIZE, remaining)
                
                flash_chunk = self._command_read_pages(offset, count)
                f.write(flash_chunk)
                
                remaining -= count
                offset += count
        
        log(f"Successfully read flash: {self.flash_size / 1024} kB read")

        if self.verify:
            self.verify_flash(filename)

    # Read flash contents and compare it with contents of given file, and raise exception if content doesn't match
    # Note: Due to the pico's 264kB of RAM, we can't just load up two copies of the firmware into memory since we'll run out of space, hence the chunking
    def verify_flash(self, filename):
        log("Verifying flash...")

        remaining = self.flash_size
        offset = 0
        
        with open(filename, "rb") as f:
            while remaining:
                count = min(CHUNK_SIZE, remaining)
                
                flash_chunk = self._command_read_pages(offset, count)
                file_chunk = f.read(count)
                
                for i in range(count):
                    if flash_chunk[i] != file_chunk[i]:
                        raise Exception(f"Failed to verify flash: flash and file differ at {hex(offset + i)}")
                
                remaining -= count
                offset += count
        
        log("Successfully verified flash: flash and file match!")
    

    ##### Erase Flash #####

    def _spi_flash_set_erase_page(self, page):
        self._i2c_write_byte(0x08, page >> 8)
        self._i2c_write_byte(0x08, page & 0xff)
        self._i2c_write_byte(0x08, 0)

    # Poll SPI Flash Read Status register until BUSY is reset
    def _spi_poll_busy(self):
        self._spi_flash_command_short(SPI_CMD_READ_STATUS)
        
        while True:
            reg = self._i2c.readfrom(I2C_DATA_ADDR, 1)[0]
            
            if (reg & 0x01) == 0:
                # Busy bit cleared
                break

    def _spi_check_write_enable(self):
        self._spi_flash_command_short(SPI_CMD_READ_STATUS)
        
        while True:
            reg = self._i2c.readfrom(I2C_DATA_ADDR, 1)[0]
            
            if (reg & 0x03) == 2:
                # Busy bit cleared and WE bit set
                break

    # Erase entire chip
    def _command_erase_1(self):
        self.spi_flash_follow_mode()
        self._spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
        self._spi_check_write_enable()
        
        # Do chip erase
        self._spi_flash_command_short(SPI_CMD_CHIP_ERASE)
        
        self._spi_poll_busy()
        self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        self.spi_flash_follow_mode_exit()

    def _command_erase_2(self):
        page = 0
        remaining = self.flash_size
        
        self.spi_flash_follow_mode()
        
        while remaining:
            self._spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
            self._spi_check_write_enable()
            
            # Do sector erase
            self._spi_flash_command_short(self.spi_cmd_sector_erase)
            self._spi_flash_set_erase_page(page)
            
            self._spi_poll_busy()
            self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
            
            # Check if need wdt restart
            self.check_wdt()
            
            page += self.sector_erase_pages
            remaining -= self.sector_erase_pages * PAGE_SIZE
        
        self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        self.spi_flash_follow_mode_exit()

    def erase_flash(self):
        log("Erasing flash...")

        if self.flash_cmd_v2:
            self._command_erase_2()
        else:
            self._command_erase_1()
        
        log("Successfully erased flash!")

        if self.verify:
            self.verify_flash_empty()

    # Read flash contents and check if each byte is 0xFF, and raise exception if any byte isn't
    # Note: Due to the pico's 264kB of RAM, we can't just load up a copy of the firmware into memory since we may run out of space, hence the chunking
    def verify_flash_empty(self):
        log("Verifying empty flash...")

        remaining = self.flash_size
        offset = 0
        
        while remaining:
            count = min(CHUNK_SIZE, remaining)
            
            flash_chunk = self._command_read_pages(offset, count)
            
            for i, byte in enumerate(flash_chunk):
                if byte != 0xFF:
                    raise Exception(f"Flash not empty: contains byte {hex(byte)} at {hex(offset + i)}")
            
            remaining -= count
            offset += count
        
        log("Successfully verified empty flash!")
    

    ##### Write Flash #####

    # Write to pages of flash memory from address to address+size from a buffer containing the data write
    def _command_write_pages(self, address, size, buffer):
        block_write_size = BLOCK_WRITE_SIZE
        remaining = size
        offset = 0
        
        self.spi_flash_follow_mode()
        
        while remaining:
            count = min(block_write_size, remaining)
            
            addr_H = (address >> 16) & 0xFF
            addr_M = (address >> 8) & 0xFF
            addr_L = address & 0xFF
            
            # Write enable
            self._spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
            
            # Check write enable bit
            self._spi_check_write_enable()
            
            # Setup write
            self._spi_flash_command_short(SPI_CMD_WORD_PROGRAM)
            
            # Set eflash page address
            self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_H]))
            self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_M]))
            self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_L]))
            
            # Wait until not busy
            self._spi_poll_busy()
            
            # Write up to BLOCK_WRITE_SIZE data
            data = buffer[offset:offset + count]
            self._i2c_write_byte(0x10, 0x20)
            self._i2c.writeto(I2C_BLOCK_ADDR, data)
            
            self._i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
            self._i2c_write_byte(0x10, 0x00)
            
            # Write disable
            self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
            
            # Wait until available
            self._spi_poll_busy()
            
            address += count
            remaining -= count
            offset += count
        
        # Check if need wdt restart
        self.check_wdt()
        
        self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        self.spi_flash_follow_mode_exit()

    def _write_flash_1(self, filename):
        remaining = self.flash_size
        offset = 0
        
        with open(filename, "rb") as f:
            while remaining:
                count = min(CHUNK_SIZE, remaining)
                
                file_chunk = f.read(count)
                
                self._command_write_pages(offset, count, file_chunk)
                
                remaining -= count
                offset += count

    def _write_flash_2(self, filename):
        block_write_size = BLOCK_WRITE_SIZE
        size = self.flash_size
        
        # We need to resend fast read command at 256KB boundary
        # If wdt_enable, we need to reduce to 4KB to avoid the wdt interrupt
        boundary = 0x40000 # 256K
        if self.wdt_enabled:
            boundary = 0x1000 # 4K
        
        self.spi_flash_follow_mode()
        
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
                self.check_wdt()
                
                # Write enable command
                self._spi_flash_command_short(SPI_CMD_WRITE_ENABLE)
                
                # AAI command
                self._spi_flash_command_short(SPI_CMD_WORD_PROGRAM)
                
                # Address of AAI command
                self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_h]))
                self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_m]))
                self._i2c.writeto(I2C_DATA_ADDR, bytes([addr_l]))
                
                # Send first two bytes of buffer
                self._i2c.writeto(I2C_DATA_ADDR, bytes(f.read(1)))
                self._i2c.writeto(I2C_DATA_ADDR, bytes(f.read(1)))
                
                # We had sent two bytes
                offset += 2
                remaining -= 2
                two_bytes_sent = True
                
                # Wait until not busy
                self._spi_poll_busy()
                
                # Enable quick AAI mode
                self._i2c_write_byte(0x10, 0x20)
            
            send_aai_cmd()
            
            while remaining:
                count = min(block_write_size, remaining)
                
                # We had sent two bytes
                if two_bytes_sent:
                    two_bytes_sent = False
                    count -= 2
                
                data = f.read(count)
                self._i2c.writeto(I2C_BLOCK_ADDR, data)
                
                remaining -= count
                offset += count
                
                # We need to resend AAI write command at boundary
                if (offset % boundary == 0) and remaining:
                    
                    # Disable quick AAI mode
                    self._i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
                    self._i2c_write_byte(0x10, 0x00)
                    
                    # Write disable command
                    self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
                    
                    send_aai_cmd()
        
        # Disable quick AAI mode
        self._i2c.writeto(I2C_DATA_ADDR, bytes([0xFF]))
        self._i2c_write_byte(0x10, 0x00)
        
        # Write disable command
        self._spi_flash_command_short(SPI_CMD_WRITE_DISABLE)
        
        # Exit follow mode
        self.spi_flash_follow_mode_exit()

    def _write_flash_3(self, filename):
        # TODO
        pass

    def write_flash(self, filename):
        # Erase flash before writing
        self.erase_flash()

        log(f"Writing {self.flash_size / 1024} kB...")

        if self.flash_cmd_v2:
            if self.eflash_type == EFLASH_TYPE_8315:
                self._write_flash_2(filename)
            elif self.eflash_type == EFLASH_TYPE_KGD:
                self._write_flash_3(filename)
            else:
                raise Exception("Failed to write flash: invalid EFLASH TYPE!")
        else:
            self._write_flash_1(filename)
        
        log(f"Successfully written flash: {self.flash_size / 1024} kB written")

        if self.verify:
            self.verify_flash(filename)


##### Main #####

if __name__ == "__main__":

    # Wait for button press
    while not button_pressed:
        if button.value():
            button_pressed = True

    # Blink LED for success to signal start
    blink_led_success()

    clear_log()


    flasher = ITEFlasher(
        sda_pin,
        scl_pin,
        i2c_freq=i2c_freq,
        send_waveform=send_waveform,
        verify=verify,
        disable_watchdog=disable_watchdog,
        disable_protect_path=disable_protect_path
    )

    flasher.connect()


    if mode == Mode.READ:
        try:
            flasher.read_flash(firmware_file)
        except Exception as e:
            error("Failed to read flash!", e)
    
    elif mode == Mode.ERASE:
        try:
            flasher.erase_flash()
        except Exception as e:
            error("Failed to erase flash!", e)
    
    elif mode == Mode.WRITE:
        try:
            flasher.write_flash(firmware_file)
        except Exception as e:
            error("Failed to write flash!", e)


    # Endlessly blink the LED to signify the end of the script
    while True:
        blink_led(0.3)
        utime.sleep(0.3)
