## BOTW Mouse Camera Mod (Cemu)

This mod lets the user control the Breath of the Wild camera with a mouse on Cemu, with smooth orbit, precise aiming, and game-native feel. This project exists thanks to the groundwork and ideas from etra0 and LibreVR — their work is referenced throughout and credited here.

### What this mod does
- Replaces right-stick camera with a mouse-driven orbit camera
- Scroll-wheel zoom 
- Clean toggle to enable/disable the mod at runtime

### Components (release folder)
- `botw_mousecam.dll` — the camera logic injected into Cemu
- `injector.exe` — the tiny helper that injects the DLL into Cemu once the game is loaded
- `position_finder.exe` — a self-contained helper that locates key runtime addresses safely and reliably

### Quick start
1. Launch Cemu and load into the game world.
2. Run `injector.exe` (from this mod's `release/` folder).
3. After a short initialization, you'll be able switch to mouse control.
4. Keys:
   - F3: Toggle the mod on/off 
   - F4: Open the mod configuration menu
   - Mouse wheel: Zoom in and out
   - Middle mouse button: Reset zoom to default
   - Other mouse buttons: Emulate the buttons of your choice


### How it works 
- `injector.exe` attaches to the Cemu process and loads `botw_mousecam.dll`.
- `position_finder.exe` finds the player/camera/state addresses safely, and shares them with the DLL via shared memory.
- The DLL:
  - Reads Link position 
  - Maintains a smooth-follow focus point 
  - Detects player state to adjust the view during aiming (subtle right/up offset with smooth blending and a small FOV change).
  - Keeps wheel zoom independent and smooth.

All credit to etra0 and LibreVR for foundational research and prior art that made this possible. This project stands on their shoulders.

### Configuration
- Press F4 in-game to open the configuration menu.
- Settings include mouse sensitivity, zoom behavior, and other camera options.


### Build (developers)
Requirements:
- Windows x64
- Rust (stable MSVC toolchain) for the DLL and injector
- .NET 6 SDK (x64) for `position_finder`

Steps:
- Clean build Rust workspace (DLL + injector):
  - `cargo clean && cargo build --release`
- Publish `position_finder` as a single-file, self-contained exe:
  - `dotnet publish position_finder/position_finder.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -p:IncludeNativeLibrariesForSelfExtract=true -p:IncludeAllContentForSelfExtract=true -o position_finder/publish`
- Place artifacts into root `release/`:
  - `release/botw_mousecam.dll`
  - `release/injector.exe`
  - `release/position_finder.exe`

- Or just use the build_all.bat that does all the above

### Troubleshooting
- "Nothing happens": ensure you are in-game (not main menu) before running `injector.exe`.
- Antivirus false positives: commonplace for small injectors. Add an exclusion for the folder if needed.
- Mouse not moving the camera: press F3 to ensure the mod is active; press F4 to confirm config bindings.
- Mod never initalizes: mod only initializes when you are in game,and menus closed.Its best if you only launch the mod when you are in world.since other scenarios might cause crashes.


### Credits
- Author: **mcrib884**
- Developed thanks to **etra0** and **LibreVR** — their tools, research, and prior projects made this mod possible.


### License
See `LICENSE` in this repository.

### Support / Donations
I'm not accepting donations for myself. If you want to support me, please donate to a charity — preferably one focused on children of Palestine— and let me know about it. That would mean the most.

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- **Bug Reports**: Use [GitHub Issues](https://github.com/yourusername/botw-mousecam/issues)
- **Feature Requests**: Use [GitHub Discussions](https://github.com/yourusername/botw-mousecam/discussions)
- **Documentation**: Check the [Wiki](https://github.com/yourusername/botw-mousecam/wiki)

## 🎁 Donations

I don't accept personal donations. If this mod has helped you, please consider donating to a charity that supports children in need, particularly those affected by conflict. Let me know if you do - it would mean the world to me.

---

**Made with ❤️ by [mcrib884](https://github.com/mcrib884)**


