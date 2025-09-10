# BOTW Position Finder

A standalone position finder executable based on the botw_editor architecture that extracts Link's position data from Cemu BOTW and provides it to the mousecam dll.

## Overview

This position finder replaces the old position_finder and position_finder_c implementations with a more robust solution that:

- Uses the exact same memory scanning techniques as botw_editor
- Runs as a standalone executable
- Communicates with the mousecam dll via shared memory
- Provides real-time Link position updates for enhanced camera tracking

## Architecture

The position finder uses botw_editor's proven memory scanning approach:

1. **Process Detection**: Locates the Cemu process
2. **Memory Region Finding**: Searches for the correct BOTW memory region using known size patterns
3. **Pattern Matching**: Uses the same byte pattern search as botw_editor to find Link's coordinates
4. **Validation**: Ensures coordinates are reasonable before reporting them
5. **Shared Memory**: Communicates the position address to mousecam dll

## Building

Requirements:
- .NET 6.0 or later
- Visual Studio 2022 or .NET CLI

### Using .NET CLI

```bash
cd position_finder
dotnet build -c Release
```

### Using Visual Studio

1. Open `position_finder.csproj` in Visual Studio
2. Build in Release configuration

## Usage

### Automatic Mode (Recommended)

The mousecam dll will automatically start the position finder when needed. Simply:

1. Build the position finder and place `position_finder.exe` in the same directory as the mousecam dll
2. Inject the mousecam dll into Cemu as usual
3. The position finder will start automatically and begin scanning for Link's position

### Manual Mode

You can also run the position finder manually for testing:

```bash
position_finder.exe
```

The console will show:
- Process detection status
- Memory scanning progress
- Found position addresses
- Current Link coordinates
- Shared memory communication status

## Shared Memory Interface

The position finder communicates with the mousecam dll through a shared memory region named "BotwPositionData" with the following structure:

```csharp
struct SharedPositionData
{
    public ulong position_address;  // Memory address where Link's position is stored
    public ulong last_update;       // Unix timestamp of last update
    public uint is_valid;           // 1 if position is valid, 0 otherwise
}
```

## Memory Pattern

The position finder uses botw_editor's coordinate finding pattern:
```
Pattern: [3, 1, 61, 47, 206, 179, 16, -1, -1, -1, 255, 255, 0, 1, 7, 255]
Offset: +102 bytes from pattern start
```

This pattern locates the memory address where Link's X, Y, Z coordinates are stored as consecutive 32-bit big-endian floats.

## Coordinate Format

Link's position is stored as three consecutive 32-bit floats in big-endian format:
- X coordinate: bytes 0-3
- Y coordinate: bytes 4-7
- Z coordinate: bytes 8-11

## Troubleshooting

### "Waiting for Cemu process..."
- Ensure Cemu is running
- Make sure BOTW is loaded in Cemu

### "Cannot access Cemu process memory"
- Run as administrator
- Check Windows UAC settings
- Ensure Cemu isn't running as admin if position finder isn't

### "Position not found"
- Wait for BOTW to fully load
- Try moving Link around in the game
- Check that you're using a supported BOTW version

### "Position address became invalid"
- Normal when loading save files or changing areas
- The position finder will automatically rescan

## Performance

- Memory scan time: 2-5 seconds typically
- Update frequency: 1 Hz (once per second)
- Memory usage: <10MB
- CPU usage: Minimal after initial scan

## Compatibility

Supports the same BOTW versions as botw_editor:
- BOTW v1.5.0 (Wii U)
- Various memory region sizes automatically detected
- Works with Cemu's recompiler and interpreter modes

## Integration with Mousecam DLL

The mousecam dll will:
1. Automatically start position_finder.exe if not running
2. Connect to shared memory
3. Use the provided position address for enhanced camera tracking
4. Fall back to camera focus point if position finder fails

This provides the best possible camera experience with accurate Link position tracking.
