# TruePic III Hardware Memory Map & MMIO Architecture

<a id="memory-domains"></a>
## TruePic III Memory Domains

The Olympus TruePic III image processor (Sanyo Coach / SG155 platform) establishes a 32-bit physical address space partitioned into eight primary operational domains spanning `0x40000000` through `0xE081FFFF`:

| Domain Name | Start Address | End Address | Size | Permissions | Description |
|:---|:---|:---|:---|:---|:---|
| **Section 1 SDRAM (NPROG)** | `0x40000000` | `0x403F50E7` | 4,149,416 B (4.15 MB) | RX | Cached ARM executable program code, literal pools, and dispatchers |
| **Section 2 SDRAM (NDATA)** | `0x403F5108` | `0x40855967` | 4,589,568 B (4.59 MB) | RO | Cached static assets, fonts, localization strings, GUI bitmaps, wave tables |
| **Uncached RAM Buffers** | `0x41F00000` | `0x41F7FFFF` | 524,288 B (512 KB) | RW | Non-cached high-speed DMA buffers, preview framebuffers, video FIFOs |
| **System State Blackboard** | `0x41F80000` | `0x41F9FFFF` | 131,072 B (128 KB) | RW | Global operating blackboard, master state struct, idle activity timers |
| **Banked Task Stacks** | `0x41FA0000` | `0x41FD0000` | 196,608 B (192 KB) | RW | RTOS task stacks, IRQ exception stack (`0x41fcf000`), system stack (`0x41fd0000`) |
| **MMIO SDRAM Controller** | `0x80410000` | `0x8041FFFF` | 65,536 B (64 KB) | RW_MMIO | SDRAM timing parameters, refresh interval counters, bus arbitration |
| **MMIO DMA & NAND Controller** | `0xC04C0000` | `0xC04CFFFF` | 65,536 B (64 KB) | RW_MMIO | High-speed DMA channels, NAND Flash Controller, FIFO buffer latches |
| **MMIO Timers/Interrupts/DAC/ISP** | `0xE0000000` | `0xE081FFFF` | 8,519,680 B (8.12 MB) | RW_MMIO | Hardware Timers, Interrupt Controller, GPIO Keypad, Video DAC, ISP, Scaler |

---

<a id="mmio-peripherals"></a>
## Hardware MMIO Peripherals Catalog

The camera utilizes seven memory-mapped hardware peripheral blocks for system control, capture processing, and video composite output:

### 1. SDRAM Controller (`0x80410000`)
- **Base Address**: `0x80410000`
- **Address Range**: `0x80410000` – `0x8041FFFF` (64 KB)
- **Primary Register**: `MMIO_SDRAM_TimingCtrl` (`0x80410000`)
- **Key Functionality**: Controls the SDRAM Controller, bus arbitration, CAS latency (CL2 / CL3), row precharge time ($t_{RP}$), and auto-refresh counter intervals across the shared 32 MB SDRAM bus.

### 2. DMA & NAND Controller (`0xC04C0000`)
- **Base Address**: `0xC04C0000`
- **Address Range**: `0xC04C0000` – `0xC04CFFFF` (64 KB)
- **Primary Registers**: `MMIO_NAND_CmdStatus` (`0xC04C0000`), Buffer FIFO `MMIO_NAND_BufferData` (`0xC04CC000`)
- **Key Functionality**: Integrated DMA Controller channels and NAND Flash Controller. Handles command and address latches (CLE/ALE), chip enable, hardware ECC computation, and block-level data bursts to internal 47MB flash and xD-Picture Cards.

### 3. Timers & Interrupt Controller (`0xE0000000` / `0xE0010000`)
- **Base Address**: `0xE0000000` (Subsystem base: `0xE0010000`)
- **Address Range**: `0xE0000000` – `0xE001FFFF` (128 KB)
- **Primary Registers**: INTC Status `MMIO_INTC_Status` (`0xE0010000`), INTC Mask `MMIO_INTC_Mask` (`0xE0010004`), Timer Base `MMIO_TIMERS_Base` (`0xE0010040`)
- **Key Functionality**: Central Interrupt Controller and hardware Timer registers. Prioritizes 100 ms RTOS tick timer, capture exposure synchronizers, keypad scan interrupts, and USB bulk transfer triggers into ARM IRQ mode (`CPSR 0xd2`).

### 4. GPIO Keypad Matrix (`0xE0200000`)
- **Base Address**: `0xE0200000`
- **Address Range**: `0xE0200000` – `0xE020FFFF` (64 KB)
- **Primary Registers**: `MMIO_GPIO_Data` (`0xE0200000`), `MMIO_GPIO_Direction` (`0xE0200004`), Input Matrix Lines (`0xE0211094`, `0xE0223291`)
- **Key Functionality**: GPIO input/output lines scanning the physical button Keypad, rotary top Mode Dial (Auto, P, A, S, M, Scene, Movie, Guide), half-press shutter S1, full-press shutter S2, zoom switches, and composite video cable detection.

### 5. Image Signal Processor (ISP) (`0xE0400000`)
- **Base Address**: `0xE0400000`
- **Address Range**: `0xE0400000` – `0xE04FFFFF` (1 MB)
- **Primary Registers**: Pipeline Control `MMIO_ISP_PipelineCtrl` (`0xE0400000`), Sensor Timing (`0xE0401001`), 3A Exposure Matrix (`0xE0422003`, `0xE04C0003`)
- **Key Functionality**: High-speed CCD Sensor interface, analog front-end (AFE) timing generator, auto-exposure/autofocus/auto-white-balance (3A) loops, defect pixel interpolation (`anji_hakuten_pos`), and draft subsampling for 30 fps preview streaming.

### 6. Video DAC Compositor (`0xE0600000`)
- **Base Address**: `0xE0600000`
- **Address Range**: `0xE0600000` – `0xE06FFFFF` (1 MB)
- **Primary Registers**: `MMIO_VIDEO_DacCtrl` (`0xE0600000`), Output Selector (`0xE0601100`), Timing Encoder (`0x4013ecf0`)
- **Key Functionality**: 2D graphics hardware compositor and Video DAC. Blends live preview sensor frames with the transparent OSD graphic overlay plane, driving digital TFT LCD/EVF signals and generating analog NTSC/PAL composite television video signals.

### 7. Hardware JPEG Scaler (`0xE0800000`)
- **Base Address**: `0xE0800000`
- **Address Range**: `0xE0800000` – `0xE081FFFF` (128 KB)
- **Primary Registers**: Codec Control `MMIO_JPEG_CodecCtrl` (`0xE0800000`), Config (`0xE0804001`), Downscaler (`0xE0811000`)
- **Key Functionality**: Hardware JPEG compression/decompression engine with dedicated DCT hardware accelerator and image Scaler. Enables rapid burst shooting (up to 15 fps) and motion JPEG (AVI) video encoding.

---

<a id="system-blackboard"></a>
## System State Blackboard Architecture

The System State Blackboard resides in dedicated uncached SDRAM at `0x41f80000`:

- **Master System State Struct (`0x41f8ddcc`)**: Stores global operating variables including current shooting mode, active dial position, zoom step, battery status, and display destination at offset `+0x5a`.
- **Inactivity Countdown Timer (`0x41f8ddac`)**: Ticks down toward standby sleep (180s timeout, event `0xca0f`) and LCD backlight dimming (150s timeout, event `0xca0e`).
- **Playback State Struct (`0x41f8df04`)**: Stores file navigation pointers and video destination during playback mode at offset `+0x5a` (`0x41f8df5e`).
- **Battery Voltage ADC (`0x41f8ddfc`)**: Stores digitized battery cell voltage for low-battery shutdown thresholds.