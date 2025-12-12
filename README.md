# Pico ITE Flasher

An adaptation of Chromium OS's [iteflash](https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/platform/ec/util/iteflash.cc) for the Raspberry Pi Pico. The script supports reading, erasing, writing and verifying the flash of various ITE EC chips.

## Setup

The diagram below shows how to set up the pico:

<img width="1641" height="1061" alt="image" src="https://github.com/user-attachments/assets/329112b5-af76-4ace-bacf-f9903c56ef2a" />

SDA and SCL should be soldered to the EC chip's SDA and SCL test points respectively on the laptop motherboard (consult the schematics of your motherboard to find where these are).

The Pico can be powered by connecting it to one of the laptop's USB ports. Doing this means the Pico automatically shares ground with the laptop, which is necessary for reliable I2C communication between the Pico and the EC chip over the SDA and SCL wires. If you cannot or do not want to power the Pico via a laptop USB port, and instead power the Pico by some other means, then to make sure that ground is shared, connect another wire to a ground pin on the Pico and solder it to a ground test point on the laptop's motherboard.

Note that the SDA and SCL lines need to be pulled up to 3.3V for the I2C communication to work. The laptop motherboard should automatically do this so you do not need to add your own pull-up resistors, but if you were to flash a standalone chip without a motherboard, then you would have to pull up these lines yourself (along with powering the chip yourself of course).

The laptop motherboard can be powered by plugging in the laptop's power supply, which will provide power to the EC chip and pull up the SDA and SCL lines. Do this as the last step before beginning the flash process, and avoid touching the motherboard from this point onward until you unplug the motherboard when done.

## Usage

In the script's configuration section, set the `mode` to either `Mode.READ`, `Mode.ERASE` or `Mode.WRITE` depending on whether you want to read from, erase, or write to the chip respectively. Set the `firmware_file` to specify the filename to use when writing to or reading from the chip. If using different pins on the Pico to the ones in the diagram above, then change the pin variables too.

Save the script to your Raspberry Pi Pico (e.g. using the Thonny IDE), and also save the firmware file to write (with the same name as specified by `firmware_file` in the script) if wanting to write to the chip, then follow the setup above.

Once the pico and motherboard are powered on, the script will automatically run, waiting for the button to be pressed. Press the button to begin the flashing process, and the Pico's built in LED will blink throughout to indicate status. Once complete, the LED should blink endlessly, and at this point the motherboard and the Pico can be powered off.

If reading from the chip, the firmware dump can be accessed by connecting the Pico to a computer and using Thonny to view the filesystem. From here, the log file that the Pico has written to during the flash process can also be viewed.
