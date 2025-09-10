use crate::utils::*;
use crate::read_coordinates_safely;

use nalgebra_glm as glm;
use std::sync::Mutex;
use log::{debug, info};

// Default third-person camera distance (meters)
const DEFAULT_DISTANCE: f32 = 6.5; // 30% farther than previous 5.0

// Magnesis focus smoothing
// If the target focus jumps (e.g., when starting to pull a new object),
// interpolate the focus over this duration to avoid snapping.
const MAGNESIS_FOCUS_SMOOTH_DURATION: f32 = 0.25; // seconds (between 0.2-0.3s as requested)
const MAGNESIS_FOCUS_SNAP_THRESHOLD: f32 = 1.0;   // meters change to trigger smoothing

#[derive(Clone, Copy)]
pub struct Vec3BE(pub [FloatBE; 3]);

#[derive(Clone, Copy)]
pub struct FloatBE(u32);

impl From<Vec3BE> for glm::TVec3<f32> {
    fn from(v: Vec3BE) -> Self {
        let v = v.0;
        glm::vec3(v[0].into(), v[1].into(), v[2].into())
    }
}

impl From<glm::TVec3<f32>> for Vec3BE {
    fn from(v: glm::TVec3<f32>) -> Self {
        Vec3BE([v[0].into(), v[1].into(), v[2].into()])
    }
}

impl From<f32> for FloatBE {
    fn from(val: f32) -> Self {
        FloatBE(val.to_bits().to_be())
    }
}

impl From<FloatBE> for f32 {
    fn from(val: FloatBE) -> f32 {
        f32::from_bits(u32::from_be(val.0))
    }
}

#[repr(C)]
pub struct GameCamera {
    pub pos: Vec3BE,
    pub focus: Vec3BE,
    pub rot: Vec3BE,
    pub fov: FloatBE,
}

impl std::fmt::Debug for GameCamera {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ptr = self as *const GameCamera as usize;
        let pos: glm::Vec3 = self.pos.into();
        let focus: glm::Vec3 = self.focus.into();

        f.debug_struct("GameCamera")
            .field("self", &format_args!("{:x}", ptr))
            .field("pos", &pos)
            .field("focus", &focus)
            .field("fov", &(f32::from(self.fov)))
            .finish()
    }
}

pub struct ZoomState {
    pub pending_zoom: f32,     // accumulated zoom to apply
    pub zoom_start_time: Option<std::time::Instant>,
    pub zoom_duration: f32,    // current zoom animation duration
    pub initial_distance: f32, // distance when zoom started
    pub zoom_count: u32,       // number of zoom steps in current sequence
    pub final_applied: bool,   // whether final zoom position has been set
}

impl ZoomState {
    pub fn new() -> Self {
        Self {
            pending_zoom: 0.0,
            zoom_start_time: None,
            zoom_duration: 0.5,
            initial_distance: 5.0,
            zoom_count: 0,
            final_applied: false,
        }
    }
}

pub struct OrbitCamera {
    pub player_pos: glm::Vec3,
    pub smooth_player_pos: glm::Vec3,  // Smoothed/interpolated position
    pub theta: f32,  // horizontal angle
    pub phi: f32,    // vertical angle  
    pub target_theta: f32, // Target horizontal angle for smooth rotation
    pub target_phi: f32,   // Target vertical angle for smooth rotation
    pub distance: f32,
    pub target_distance: f32, // Target distance for smooth zoom
    pub initialized: bool,
    pub last_update_time: std::time::Instant, // For dynamic frame timing
    pub zoom_state: ZoomState, // smooth zoom state
    pub phonecamera_zoom_active: bool, // Whether PhoneCamera zoom is currently active
    pub pre_phonecamera_distance: f32, // Distance before PhoneCamera zoom was applied
    pub phonecamera_zoom_factor: f32, // Current zoom factor (10x to 20x)
    
    // Magnesis rotation protection
    pub magnesis_rotation_protected: bool, // Whether camera rotation is protected from magnesis
    pub saved_theta: f32, // Saved horizontal angle when magnesis activates
    pub saved_phi: f32,   // Saved vertical angle when magnesis activates
    pub saved_focus_x: f32, // Saved focus point X when magnesis activates
    pub saved_focus_y: f32, // Saved focus point Y when magnesis activates
    pub saved_focus_z: f32, // Saved focus point Z when magnesis activates

    // Smoothed focus handling for magnesis
    pub focus_smooth: glm::Vec3,
    pub focus_smooth_from: glm::Vec3,
    pub focus_smooth_to: glm::Vec3,
    pub focus_smooth_start: Option<std::time::Instant>,
    pub focus_smooth_duration: f32,
}

impl OrbitCamera {
    pub fn new() -> Self {
        Self {
            player_pos: glm::vec3(0.0, 0.0, 0.0),
            smooth_player_pos: glm::vec3(0.0, 0.0, 0.0),
            theta: 0.0,
            phi: std::f32::consts::PI / 4.0, // 45 degrees
            target_theta: 0.0,
            target_phi: std::f32::consts::PI / 4.0, // 45 degrees
            distance: DEFAULT_DISTANCE,
            target_distance: DEFAULT_DISTANCE,
            initialized: false,
            last_update_time: std::time::Instant::now(),
            zoom_state: ZoomState::new(),
            phonecamera_zoom_active: false,
            pre_phonecamera_distance: DEFAULT_DISTANCE,
            phonecamera_zoom_factor: 10.0, // Default 10x zoom
            
            // Initialize magnesis rotation protection
            magnesis_rotation_protected: false,
            saved_theta: 0.0,
            saved_phi: std::f32::consts::PI / 4.0,
            saved_focus_x: 0.0,
            saved_focus_y: 0.0,
            saved_focus_z: 0.0,

            // Focus smoothing defaults
            focus_smooth: glm::vec3(0.0, 0.0, 0.0),
            focus_smooth_from: glm::vec3(0.0, 0.0, 0.0),
            focus_smooth_to: glm::vec3(0.0, 0.0, 0.0),
            focus_smooth_start: None,
            focus_smooth_duration: MAGNESIS_FOCUS_SMOOTH_DURATION,
        }
    }

    pub fn initialize_from_camera(&mut self, gc: &GameCamera, link_pos: Option<glm::Vec3>) {
        let pos: glm::Vec3 = gc.pos.into();
        let focus: glm::Vec3 = gc.focus.into();
        
        // Use Link's actual position if available, otherwise use camera focus
        let player_position = match link_pos {
            Some(mut link_pos) => {
                link_pos.y += 1.8; // Add torso offset
                link_pos
            }
            None => focus
        };
        
        // Use reset_position to initialize without smoothing
        self.reset_position(player_position);
        
        // Initialize focus smoothing state to current player/focus position
        self.focus_smooth = player_position;
        self.focus_smooth_from = player_position;
        self.focus_smooth_to = player_position;
        self.focus_smooth_start = None;
        self.focus_smooth_duration = MAGNESIS_FOCUS_SMOOTH_DURATION;
        
        // Set consistent default distance instead of preserving game camera distance
        self.distance = DEFAULT_DISTANCE; // Standard BOTW camera distance
        self.target_distance = DEFAULT_DISTANCE; // Initialize target distance
        
        // Calculate angles from current game camera for smooth transition
        let offset = pos - player_position;
        if offset.x != 0.0 || offset.z != 0.0 {
            self.theta = offset.z.atan2(offset.x);
            self.phi = (offset.x.powi(2) + offset.z.powi(2)).sqrt().atan2(offset.y).clamp(0.05, std::f32::consts::PI - 0.05);
        }
        
        self.initialized = true;
        self.last_update_time = std::time::Instant::now();
    }

    /// Immediately reset camera position and orientation without smoothing
    pub fn reset_position(&mut self, new_pos: glm::Vec3) {
        self.player_pos = new_pos;
        self.smooth_player_pos = new_pos;
        
        // Reset camera orientation to default values
        self.theta = 0.0;
        self.phi = std::f32::consts::PI / 4.0;

        info!("[CAMERA] Position and orientation reset to: ({:.2}, {:.2}, {:.2})", new_pos.x, new_pos.y, new_pos.z);
    }
    
    /// Snap camera to new position while preserving current rotation
    /// Used for menu detection - maintains camera angle but moves to player position
    pub fn snap_to_position(&mut self, new_pos: glm::Vec3) {
        self.player_pos = new_pos;
        self.smooth_player_pos = new_pos;
        
        // Keep existing theta and phi values (don't reset rotation)
        
        info!("[CAMERA] Position snapped to: ({:.2}, {:.2}, {:.2}) keeping rotation theta={:.3}, phi={:.3}", 
              new_pos.x, new_pos.y, new_pos.z, self.theta, self.phi);
    }

    pub fn smooth_position_update(&mut self, new_pos: glm::Vec3) {
        let now = std::time::Instant::now();
        let delta_time = (now - self.last_update_time).as_secs_f32().clamp(0.0002, 0.016); // Up to 5000fps, min 60fps for ultra-high refresh support
        self.last_update_time = now;
        
        if !self.initialized {
            self.reset_position(new_pos);
            return;
        }

        // Update position
        self.player_pos = new_pos;
        
        // PROPER ACCUMULATIVE SMOOTHING
        let position_diff = new_pos - self.smooth_player_pos;
        
        // GENTLE POSITION SMOOTHING - Very slight smoothing for natural camera movement
        let base_smoothing_speed = 8.0; // Much gentler base speed for subtle smoothing
        let distance_to_target = glm::length(&position_diff);
        
        // Gentle adaptive smoothing with subtle adjustments
        let smoothing_speed = if distance_to_target > 10.0 {
            base_smoothing_speed * 4.0 // Faster catch-up for teleports/fast travel, but still smooth
        } else if distance_to_target > 3.0 {
            base_smoothing_speed * 2.5 // Moderate speed for running/jumping
        } else if distance_to_target > 0.5 {
            base_smoothing_speed * 1.5 // Slightly faster for walking
        } else {
            base_smoothing_speed * 1.0 // Gentle following for close movement
        };
        let movement_distance = glm::length(&position_diff);
        
        // Calculate how much to move this frame based on consistent speed
        let move_amount = smoothing_speed * delta_time;
        
        if movement_distance > 0.001 { // Only move if there's meaningful distance
            // ANTI-JITTER: Enhanced smoothing with micro-movement detection
            let move_ratio = (move_amount / movement_distance).min(1.0);
            
            // ANTI-JITTER: Optimized smoothing based on movement speed
            if movement_distance < 0.02 { // Very small movements (under 2cm)
                // Use exponential smoothing for tiny movements to prevent micro-jitter
                let micro_smoothing_factor = 0.35; // More aggressive smoothing for micro-movements
                self.smooth_player_pos = self.smooth_player_pos * (1.0 - micro_smoothing_factor) + new_pos * micro_smoothing_factor;
            } else if movement_distance > 2.0 { // High-speed movement (over 2m per frame)
                // For very fast movement, use more aggressive linear interpolation to prevent lag
                let high_speed_ratio = (move_amount / movement_distance).min(0.8); // Cap at 80% for stability
                self.smooth_player_pos = self.smooth_player_pos + position_diff * high_speed_ratio;
            } else {
                // Normal linear interpolation for regular movement
                self.smooth_player_pos = self.smooth_player_pos + position_diff * move_ratio;
            }
        }
        
        // Update zoom state first
        self.update_smooth_zoom();
        
        // ULTRA-FAST zoom smoothing - no lag on zoom changes
        let zoom_diff = self.target_distance - self.distance;
        let zoom_move_amount = 35.0 * delta_time; // Ultra-fast zoom for 1200Hz refresh rates
        if zoom_diff.abs() > 0.005 { // Smaller threshold for more responsive zoom
            let zoom_ratio = (zoom_move_amount / zoom_diff.abs()).min(0.9); // Slightly more aggressive
            self.distance = self.distance + zoom_diff * zoom_ratio;
        }
        
        // Distance clamping: Allow negative distances in PhoneCamera mode (camera past player)
        // In normal mode, prevent camera from passing through the player
        if !self.phonecamera_zoom_active {
            // Normal mode: minimum distance of 0.5m to keep camera behind/around player
            self.distance = self.distance.max(0.5);
            self.target_distance = self.target_distance.max(0.5);
        }
        // PhoneCamera mode: Allow negative distances (no clamping) for camera past player
        
        // SMOOTH angle interpolation for camera reset (only when targets are set)
        // Skip rotation smoothing if magnesis protection is active
        if !self.magnesis_rotation_protected {
            let theta_diff = self.target_theta - self.theta;
            let phi_diff = self.target_phi - self.phi;
            
            // Only interpolate if there's a meaningful difference
            if theta_diff.abs() > 0.01 || phi_diff.abs() > 0.01 {
                let angle_move_speed = 8.0 * delta_time; // Smooth rotation speed
                
                // Smooth theta interpolation
                if theta_diff.abs() > 0.01 {
                    let theta_ratio = (angle_move_speed / theta_diff.abs()).min(0.2); // Gentle smoothing
                    self.theta = self.theta + theta_diff * theta_ratio;
                }
                
                // Smooth phi interpolation
                if phi_diff.abs() > 0.01 {
                    let phi_ratio = (angle_move_speed / phi_diff.abs()).min(0.2); // Gentle smoothing
                    self.phi = self.phi + phi_diff * phi_ratio;
                    self.phi = self.phi.clamp(0.05, std::f32::consts::PI - 0.05); // Keep within valid range
                }
            }
        }
    }

    pub fn update_orbit(&mut self, delta_x: f32, delta_y: f32, zoom_delta: f32) {
        if !self.initialized {
            return;
        }

        // ULTRA-RESPONSIVE MOUSE ROTATION - MINIMAL OPERATIONS
        // Direct rotation updates with combined calculation
        self.theta += delta_x;
        self.phi = (self.phi - delta_y).clamp(0.05, std::f32::consts::PI - 0.05);
        
        // Update target angles to match current angles when user moves mouse
        // This stops any ongoing smooth reset when user takes control
        if delta_x != 0.0 || delta_y != 0.0 {
            self.target_theta = self.theta;
            self.target_phi = self.phi;
        }
        
        // Handle zoom if needed (disabled during PhoneCamera mode)
        if zoom_delta != 0.0 {
            self.handle_smooth_zoom(zoom_delta);
        }
    }
    
    pub fn reset_zoom_to_default(&mut self) {
        // Smooth reset to default 5.0 distance using existing interpolation
        self.target_distance = DEFAULT_DISTANCE;
        
        // Clear any ongoing zoom animation to avoid conflicts
        self.zoom_state.pending_zoom = 0.0;
        self.zoom_state.zoom_start_time = None;
        self.zoom_state.final_applied = false;
        self.zoom_state.zoom_count = 0;
        
        // The existing distance interpolation in smooth_position_update() will handle the smooth transition
    }
    
    /// Smoothly reset camera position and orientation to default (behind player)
    pub fn reset_camera_to_default(&mut self) {
        // Reset zoom distance smoothly
        self.target_distance = DEFAULT_DISTANCE;
        
        // Clear any ongoing zoom animation to avoid conflicts
        self.zoom_state.pending_zoom = 0.0;
        self.zoom_state.zoom_start_time = None;
        self.zoom_state.final_applied = false;
        self.zoom_state.zoom_count = 0;
        
        // Set target angles for smooth interpolation to default position (behind player)
        self.target_theta = 0.0; // Default horizontal angle (behind player)
        self.target_phi = std::f32::consts::PI / 4.0; // Default vertical angle (45 degrees)
        
        info!("[CAMERA] Smoothly resetting camera to default position behind player");
    }
    
    /// Instantly snap camera position and orientation to default (behind player) - no smooth transition
    pub fn snap_camera_to_default(&mut self) {
        // Instantly set distance (no smooth transition)
        self.distance = DEFAULT_DISTANCE;
        self.target_distance = DEFAULT_DISTANCE;
        
        // Clear any ongoing zoom animation to avoid conflicts
        self.zoom_state.pending_zoom = 0.0;
        self.zoom_state.zoom_start_time = None;
        self.zoom_state.final_applied = false;
        self.zoom_state.zoom_count = 0;
        
        // Instantly set angles to default position (behind player)
        self.theta = 0.0; // Default horizontal angle (behind player)
        self.phi = std::f32::consts::PI / 4.0; // Default vertical angle (45 degrees)
        self.target_theta = self.theta;
        self.target_phi = self.phi;
        
        info!("[CAMERA] Instantly snapped camera to default position behind player");
    }
    
    /// Save current camera rotation and focus for magnesis protection
    pub fn save_rotation_for_magnesis_protection(&mut self) {
        self.saved_theta = self.theta;
        self.saved_phi = self.phi;
        // Save current focus point (player position) for restoration
        self.saved_focus_x = self.smooth_player_pos.x;
        self.saved_focus_y = self.smooth_player_pos.y;
        self.saved_focus_z = self.smooth_player_pos.z;
        self.magnesis_rotation_protected = true;
        
        info!("[CAMERA] Saved camera rotation and focus for magnesis protection: theta={:.3}, phi={:.3}, focus=({:.3}, {:.3}, {:.3})", 
              self.saved_theta, self.saved_phi, self.saved_focus_x, self.saved_focus_y, self.saved_focus_z);
    }
    
    /// Restore camera rotation and focus from magnesis protection and disable protection
    pub fn restore_rotation_from_magnesis_protection(&mut self) {
        if self.magnesis_rotation_protected {
            info!("[CAMERA] Before restore: current theta={:.3}, phi={:.3}, focus=({:.3}, {:.3}, {:.3})", 
                  self.theta, self.phi, self.smooth_player_pos.x, self.smooth_player_pos.y, self.smooth_player_pos.z);
            info!("[CAMERA] Restoring to: saved theta={:.3}, phi={:.3}, focus=({:.3}, {:.3}, {:.3})", 
                  self.saved_theta, self.saved_phi, self.saved_focus_x, self.saved_focus_y, self.saved_focus_z);
            
            self.theta = self.saved_theta;
            self.phi = self.saved_phi;
            self.target_theta = self.theta;
            self.target_phi = self.phi;
            
            // Restore the saved focus point (player position)
            self.smooth_player_pos.x = self.saved_focus_x;
            self.smooth_player_pos.y = self.saved_focus_y;
            self.smooth_player_pos.z = self.saved_focus_z;
            self.player_pos = self.smooth_player_pos; // Keep both positions in sync
            
            self.magnesis_rotation_protected = false;
            
            info!("[CAMERA] After restore: theta={:.3}, phi={:.3}, target_theta={:.3}, target_phi={:.3}, focus=({:.3}, {:.3}, {:.3})", 
                  self.theta, self.phi, self.target_theta, self.target_phi, self.smooth_player_pos.x, self.smooth_player_pos.y, self.smooth_player_pos.z);
        }
    }

    /// Clear magnesis rotation protection WITHOUT restoring saved rotation or focus
    /// This avoids snapping the camera back to the pre-magnesis state when magnesis ends
    pub fn clear_magnesis_rotation_protection(&mut self) {
        if self.magnesis_rotation_protected {
            self.magnesis_rotation_protected = false;
            // Intentionally DO NOT modify theta/phi or player/focus positions here.
            // Keeping the current orientation and focus prevents visible snapping when magnesis is disabled.
            info!("[CAMERA] Cleared magnesis rotation protection without restoration (keeping current view)");
        }
    }

    /// Synchronize the orbit camera state to exactly match the current game camera view
    /// Use this right when magnesis turns off to prevent any snap or drift on that frame
    pub fn sync_to_game_camera(&mut self, gc: &GameCamera) {
        let pos: glm::Vec3 = gc.pos.into();
        let focus: glm::Vec3 = gc.focus.into();

        // Set the orbit pivot to the current game focus and align both smoothed and instant positions
        self.player_pos = focus;
        self.smooth_player_pos = focus;

        // Derive spherical angles and distance from current camera offset
        let offset = pos - focus;
        let horiz_len = (offset.x * offset.x + offset.z * offset.z).sqrt();
        let distance = (horiz_len * horiz_len + offset.y * offset.y).sqrt().max(0.5);

        if horiz_len > 1e-6 || offset.y.abs() > 1e-6 {
            self.theta = offset.z.atan2(offset.x);
            self.phi = horiz_len.atan2(offset.y).clamp(0.05, std::f32::consts::PI - 0.05);
        }

        self.target_theta = self.theta;
        self.target_phi = self.phi;
        self.distance = distance;
        self.target_distance = distance;

        info!(
            "[CAMERA] Synced orbit to game camera: theta={:.3}, phi={:.3}, dist={:.3}, focus=({:.3}, {:.3}, {:.3})",
            self.theta, self.phi, self.distance, focus.x, focus.y, focus.z
        );
    }

    pub fn enforce_magnesis_rotation_protection(&mut self) {
        if self.magnesis_rotation_protected {
            // Continuously enforce the saved rotation angles
            self.theta = self.saved_theta;
            self.phi = self.saved_phi;
            self.target_theta = self.theta;
            self.target_phi = self.phi;
            
            // Continuously enforce the saved focus point (player position)
            self.smooth_player_pos.x = self.saved_focus_x;
            self.smooth_player_pos.y = self.saved_focus_y;
            self.smooth_player_pos.z = self.saved_focus_z;
            self.player_pos = self.smooth_player_pos; // Keep both positions in sync
            
            // Additional debug logging to track enforcement
            static mut LAST_ENFORCE_LOG: Option<std::time::Instant> = None;
            let should_log = unsafe { LAST_ENFORCE_LOG.map_or(true, |t| t.elapsed() > std::time::Duration::from_secs(2)) };
            if should_log {
                info!("[CAMERA] Enforcing protected rotation and focus: theta={:.3}, phi={:.3}, focus=({:.3}, {:.3}, {:.3})", 
                      self.theta, self.phi, self.saved_focus_x, self.saved_focus_y, self.saved_focus_z);
                unsafe { LAST_ENFORCE_LOG = Some(std::time::Instant::now()); }
            }
        }
    }
    
    /// Apply PhoneCamera zoom when photo mode is enabled - move camera to player pivot (distance 0) and rely on FOV zoom
    pub fn apply_phonecamera_zoom(&mut self) {
        if !self.phonecamera_zoom_active {
            // Store the current distance before applying zoom
            self.pre_phonecamera_distance = self.distance;
            
            // Reset zoom factor to default 10x when first entering PhoneCamera (kept for future use)
            self.phonecamera_zoom_factor = 10.0;
            
            // PhoneCamera: Place camera exactly at the player pivot (distance = 0)
            // Orientation will be maintained and FOV will provide the zoom effect
            self.target_distance = 0.0;
            
            // No rotation changes - maintain the original viewing direction
            
            self.phonecamera_zoom_active = true;
            info!("[PHONECAMERA] Pivot zoom: {:.2}m -> {:.2}m (camera at player pivot; FOV handles zoom)",
                  self.pre_phonecamera_distance, self.target_distance);
        }
    }
    
    /// Remove PhoneCamera zoom and restore original distance and orientation
    pub fn remove_phonecamera_zoom(&mut self) {
        if self.phonecamera_zoom_active {
            // Restore the original distance
            self.target_distance = self.pre_phonecamera_distance;
            
            // Clear any ongoing zoom animation to avoid conflicts
            self.zoom_state.pending_zoom = 0.0;
            self.zoom_state.zoom_start_time = None;
            self.zoom_state.final_applied = false;
            self.zoom_state.zoom_count = 0;
            
            self.phonecamera_zoom_active = false;
            info!("[PHONECAMERA] Restored normal camera (target distance: {:.2}m)", self.target_distance);
        }
    }
    
    /// Adjust PhoneCamera zoom with mouse wheel (DISABLED)
    pub fn adjust_phonecamera_zoom(&mut self, _zoom_delta: f32) {
        // Mouse wheel zoom adjustment disabled - PhoneCamera zoom is fixed at 10x when enabled
        // No longer responds to mouse wheel input
    }
    
    /// Reset PhoneCamera to default pivot position (distance 0)
    pub fn reset_phonecamera_zoom(&mut self) {
        if self.phonecamera_zoom_active {
            // Reset to pivot position: camera at player pivot; FOV provides zoom
            self.phonecamera_zoom_factor = 10.0;
            self.target_distance = 0.0; // Camera at player pivot
            
            // No rotation changes - maintain original viewing direction
            
            info!("[PHONECAMERA] Reset to pivot position (target distance: {:.2}m)",
                  self.target_distance);
        }
    }

    fn handle_smooth_zoom(&mut self, zoom_delta: f32) {
        let now = std::time::Instant::now();
        
        // Determine zoom duration based on sequence count
        let base_duration = 0.5; // 0.5 seconds for first zoom
        let duration = match self.zoom_state.zoom_count {
            0 => base_duration,         // 0.5s for first
            1 => base_duration * 0.4,   // 0.2s for second  
            2 => base_duration * 0.2,   // 0.1s for third
            _ => base_duration * 0.2,   // 0.1s for subsequent
        };
        
        // Check if this is a new zoom sequence (more than 1 second since last zoom)
        let is_new_sequence = if let Some(start_time) = self.zoom_state.zoom_start_time {
            now.duration_since(start_time).as_secs_f32() > 1.0
        } else {
            true
        };
        
        if is_new_sequence {
            // Start new zoom sequence
            self.zoom_state.zoom_count = 0;
            self.zoom_state.initial_distance = self.distance;
            self.zoom_state.pending_zoom = 0.0;
            self.zoom_state.final_applied = false;
        }
        
        // Accumulate zoom (consistent symmetric steps)
        self.zoom_state.pending_zoom += zoom_delta * 1.0; // Symmetric zoom magnitude
        self.zoom_state.zoom_start_time = Some(now);
        self.zoom_state.zoom_duration = duration;
        self.zoom_state.zoom_count += 1;
        self.zoom_state.final_applied = false; // Reset since we have new zoom input
    }
    
    fn update_smooth_zoom(&mut self) {
        if let Some(start_time) = self.zoom_state.zoom_start_time {
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(start_time).as_secs_f32();
            
            if elapsed < self.zoom_state.zoom_duration && self.zoom_state.pending_zoom != 0.0 {
                // Calculate smooth interpolation (ease-out curve)
                let progress = elapsed / self.zoom_state.zoom_duration;
                let ease_out = 1.0 - (1.0 - progress).powi(3); // Cubic ease-out
                
                // Apply zoom with smooth curve - clamp only in normal mode, not PhoneCamera mode
                let zoom_factor = 1.0 - (self.zoom_state.pending_zoom * ease_out * 0.5);
                let new_distance = self.zoom_state.initial_distance * zoom_factor;
                
                if self.phonecamera_zoom_active {
                    // PhoneCamera mode: Allow negative distances (no clamping)
                    self.target_distance = new_distance;
                } else {
                    // Normal mode: Clamp to prevent camera passing through player
                    self.target_distance = new_distance.clamp(0.5, 50.0);
                }
                
            } else if self.zoom_state.pending_zoom != 0.0 && !self.zoom_state.final_applied {
                // Zoom animation complete, apply final zoom ONCE with appropriate clamping
                let zoom_factor = 1.0 - (self.zoom_state.pending_zoom * 0.5);
                let new_distance = self.zoom_state.initial_distance * zoom_factor;
                
                if self.phonecamera_zoom_active {
                    // PhoneCamera mode: Allow negative distances (no clamping)
                    self.target_distance = new_distance;
                } else {
                    // Normal mode: Clamp to prevent camera passing through player
                    self.target_distance = new_distance.clamp(0.5, 50.0);
                }
                
                self.zoom_state.final_applied = true; // Mark as applied to prevent re-calculation
                
            } else if elapsed > self.zoom_state.zoom_duration + 0.2 {
                // Reset for next zoom if enough time has passed
                self.zoom_state.pending_zoom = 0.0;
                self.zoom_state.zoom_start_time = None;
                self.zoom_state.final_applied = false;
            }
        }
    }

    
    /// Update or return the smoothed focus used during magnesis.
    /// If the target jumps by more than MAGNESIS_FOCUS_SNAP_THRESHOLD and no smoothing is active,
    /// begin a short ease-out smoothing over MAGNESIS_FOCUS_SMOOTH_DURATION seconds.
    pub fn update_magnesis_focus(&mut self, target: glm::Vec3) -> glm::Vec3 {
        let now = std::time::Instant::now();
        match self.focus_smooth_start {
            None => {
                // Decide if we should start smoothing based on jump size
                let jump = glm::length(&(target - self.focus_smooth));
                if jump > MAGNESIS_FOCUS_SNAP_THRESHOLD {
                    // Start smoothing from current smoothed focus toward the new target
                    self.focus_smooth_from = self.focus_smooth;
                    self.focus_smooth_to = target;
                    self.focus_smooth_start = Some(now);
                    self.focus_smooth // return current; will advance next frame
                } else {
                    // Small change: follow immediately
                    self.focus_smooth = target;
                    target
                }
            }
            Some(start_time) => {
                let elapsed = now.saturating_duration_since(start_time).as_secs_f32();
                if elapsed >= self.focus_smooth_duration {
                    // Done smoothing
                    self.focus_smooth = self.focus_smooth_to;
                    self.focus_smooth_start = None;
                    self.focus_smooth
                } else {
                    // Ease-out cubic
                    let t = (elapsed / self.focus_smooth_duration).clamp(0.0, 1.0);
                    let ease = 1.0 - (1.0 - t).powi(3);
                    self.focus_smooth = self.focus_smooth_from * (1.0 - ease) + self.focus_smooth_to * ease;
                    self.focus_smooth
                }
            }
        }
    }

    // Get camera position with immediate rotation (no smoothing on mouse input)
    // Handles both normal positive distances (camera behind player) and negative distances (camera past player)
    pub fn get_immediate_camera_position(&self, immediate_focus: glm::Vec3) -> glm::Vec3 {
        use crate::magnesis_experimental;
        if !self.initialized {
            return glm::vec3(0.0, 0.0, 0.0);
        }

        // Use smoothed distance for zoom but immediate rotation angles
        // This gives instant mouse rotation but smooth zoom transitions
        // For PhoneCamera mode: negative distance means camera goes past the player
        let effective_distance = if self.phonecamera_zoom_active {
            // In PhoneCamera mode, use the actual distance (which can be negative)
            self.distance
        } else {
            // In normal mode, ensure positive distance
            self.distance.abs().max(0.5)
        };
        
        let x = effective_distance * self.phi.sin() * self.theta.cos();
        let y = effective_distance * self.phi.cos();
        let z = effective_distance * self.phi.sin() * self.theta.sin();

        let mut pos = immediate_focus + glm::vec3(x, y, z);
        // Apply floor clamp when magnesis is active and a min height is recorded
        if magnesis_experimental::is_magnesis_control_active() {
            if let Ok(min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                if let Some(min_y) = *min_lock {
                    if pos.y < min_y { pos.y = min_y; }
                }
            }
        }
        pos
    }


}

// Global orbit camera for game-synchronized updates
pub static ORBIT_CAMERA: Mutex<Option<OrbitCamera>> = Mutex::new(None);

// Minimum camera Y (world height) during magnesis mode to prevent camera from going below start point
pub static MAGNESIS_CAMERA_MIN_Y: Mutex<Option<f32>> = Mutex::new(None);

impl GameCamera {
    pub fn consume_mouse_input(&mut self, input: &MouseInput, orbit_cam: &mut OrbitCamera, link_pos_addr: usize) {
        // Check if experimental magnesis is active
        use crate::magnesis_experimental;
        let magnesis_active = magnesis_experimental::is_magnesis_control_active();
        
        // If magnesis is not active, clear the min camera Y clamp
        if !magnesis_active {
            if let Ok(mut min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                *min_lock = None;
            }
        }
        
        // Try to get Link's position using botw_editor's method
        let link_position = if link_pos_addr != 0 {
            match read_coordinates_safely(link_pos_addr) {
                Some((x, y, z)) => {
                    let pos = glm::vec3(x, y, z);
                    Some(pos)
                }
                None => None
            }
        } else {
            None
        };

        if !orbit_cam.initialized {
            orbit_cam.initialize_from_camera(self, link_position);
            return;
        }

        // Handle magnesis mode - wait for startup capture phase before positioning camera
        if magnesis_active {
            // Ensure we record an initial floor for camera Y during magnesis as soon as it activates
            if let Ok(mut min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                if min_lock.is_none() {
                    let current_cam_pos: glm::Vec3 = self.pos.into();
                    *min_lock = Some(current_cam_pos.y);
                }
            }
            // Check if we're still in the startup capture phase (waiting for object to move first)
            let in_startup_phase = magnesis_experimental::is_in_startup_capture_phase();
            
            if in_startup_phase {
                // Still waiting for magnesis object to move first - use normal camera controls for now
                orbit_cam.update_orbit(input.orbit_x, input.orbit_y, input.zoom);
                
                // Get current target position (raw, no smoothing for rotation calculation)
                let target_pos = match link_position {
                    Some(mut pos) => {
                        // Add Y-offset to focus on Link's torso instead of feet (like game camera)
                        pos.y += 1.8; // Approximate torso height offset in meters
                        pos
                    }
                    None => {
                        // Fallback to camera focus point
                        self.focus.into()
                    }
                };

                // Update smooth player position (ONLY for smooth following, not for camera rotation)
                orbit_cam.smooth_position_update(target_pos);

                // Use normal camera positioning while waiting
                let smooth_focus = orbit_cam.smooth_player_pos; // Smooth following
        let mut new_pos = orbit_cam.get_immediate_camera_position(smooth_focus);
                
                // Clamp camera Y during magnesis startup if a floor has been recorded
                if let Ok(min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                    if let Some(min_y) = *min_lock {
                        if new_pos.y < min_y { new_pos.y = min_y; }
                    }
                }
                
                // Update camera position with smooth focus but immediate rotation
                self.pos = new_pos.into();
                self.focus = smooth_focus.into(); // Use smooth focus for jitter-free following

                // Keep magnesis focus smoothing state anchored to current focus during startup
                orbit_cam.focus_smooth = smooth_focus;
                orbit_cam.focus_smooth_from = smooth_focus;
                orbit_cam.focus_smooth_to = smooth_focus;
                orbit_cam.focus_smooth_start = None;

                // Calculate rotation (up vector) using smooth focus for stable orientation
                let up = glm::vec3(0.0, 1.0, 0.0);
                let forward = glm::normalize(&(smooth_focus - new_pos));
                let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
                let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
                
                self.rot = camera_up.into();

                // Progress experimental magnesis startup capture without moving the object
                // This polls the coordinates until they change from the initial sample
                crate::magnesis_experimental::update_magnesis_position(
                    0.0,
                    0.0,
                    0.0,
                    crate::utils::get_global_config().magnesis_sensitivity,
                );
                
                debug!("[CAMERA] Magnesis active but waiting for object movement before repositioning camera");
                return;
            }
            
            // Check if this is the initial activation and camera needs repositioning
            let needs_initial_setup = magnesis_experimental::should_reset_camera_position();
            
            if needs_initial_setup {
                // Get current target position for initial camera setup
                let target_pos = match link_position {
                    Some(mut pos) => {
                        // Add Y-offset to focus on Link's torso instead of feet (like game camera)
                        pos.y += 1.8; // Approximate torso height offset in meters
                        pos
                    }
                    None => {
                        // Fallback to camera focus point
                        self.focus.into()
                    }
                };
                
                // Update smooth player position for following
                orbit_cam.smooth_position_update(target_pos);
                
                // Reset orbit camera to initial position behind player
                let smooth_focus = orbit_cam.smooth_player_pos;
                
                // Reset orbit camera to default position: 1.5m behind and 0.5m above player
                orbit_cam.theta = std::f32::consts::PI; // Behind player (180 degrees)
                orbit_cam.phi = std::f32::consts::PI / 4.0; // 45 degrees elevation
                orbit_cam.distance = 1.5; // 1.5m distance
                orbit_cam.target_theta = orbit_cam.theta;
                orbit_cam.target_phi = orbit_cam.phi;
                orbit_cam.target_distance = orbit_cam.distance;
                
                // Record the initial camera Y as the minimum allowed height during magnesis
                let initial_cam_pos = orbit_cam.get_immediate_camera_position(smooth_focus);
                if let Ok(mut min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                    *min_lock = Some(initial_cam_pos.y);
                }

                // Initialize focus smoothing anchor so the next focus change blends in smoothly
                orbit_cam.focus_smooth = smooth_focus;
                orbit_cam.focus_smooth_from = smooth_focus;
                orbit_cam.focus_smooth_to = smooth_focus;
                orbit_cam.focus_smooth_start = None;

                info!("[CAMERA] Magnesis startup complete - camera repositioned behind player");
                
                // Mark that initial setup is done
                magnesis_experimental::mark_camera_position_reset_done();
            }
            
            // After initial setup, use normal camera controls with magnesis object updates
            orbit_cam.update_orbit(input.orbit_x, input.orbit_y, input.zoom);
            
            // Get current target position (raw, no smoothing for rotation calculation)
            let target_pos = match link_position {
                Some(mut pos) => {
                    // Add Y-offset to focus on Link's torso instead of feet (like game camera)
                    pos.y += 1.8; // Approximate torso height offset in meters
                    pos
                }
                None => {
                    // Fallback to camera focus point
                    self.focus.into()
                }
            };

            // Update smooth player position (ONLY for smooth following, not for camera rotation)
            orbit_cam.smooth_position_update(target_pos);

            // Use normal camera positioning with immediate rotation
            let smooth_focus = orbit_cam.smooth_player_pos; // Smooth following
            
            // Calculate focus point for magnesis mode - use midpoint between player and object
            let (final_focus, adjusted_camera_pos) = if let Some((obj_x, obj_y, obj_z)) = magnesis_experimental::get_current_magnesis_position() {
                let object_pos = glm::vec3(obj_x, obj_y, obj_z);
                let player_pos = smooth_focus;
                
                // Calculate midpoint between player and object for smooth focus tracking
                let midpoint = (player_pos + object_pos) * 0.5;
                
                // Calculate distance between player and object
                let player_object_distance = glm::length(&(object_pos - player_pos));
                
                // Adjust camera distance based on player-object distance
                // Base distance of 5.0m, but scale up when object is far from player
                let base_camera_distance = orbit_cam.distance; // Use current zoom level
                
                // Smooth distance factor calculation with better scaling
                // When objects are close (< 3m apart): minimal scaling (factor ~1.0)
                // When objects are far (> 10m apart): significant scaling to keep both in view
                let distance_factor = if player_object_distance <= 3.0 {
                    1.0 // No scaling for close objects
                } else if player_object_distance <= 10.0 {
                    // Gradual scaling from 1.0 to 2.0 for medium distances
                    1.0 + (player_object_distance - 3.0) / 7.0
                } else {
                    // More aggressive scaling for very distant objects
                    2.0 + (player_object_distance - 10.0) / 10.0
                };
                
                let adjusted_camera_distance = (base_camera_distance * distance_factor).min(50.0); // Cap at 50m
                
                // Smooth the focus when the target midpoint jumps (e.g., new object pull)
                let smoothed_focus = orbit_cam.update_magnesis_focus(midpoint);
                
                debug!("[CAMERA_FOCUS] Using midpoint for focus: obj=({:.2}, {:.2}, {:.2}), player=({:.2}, {:.2}, {:.2}), midpoint=({:.2}, {:.2}, {:.2}), smoothed=({:.2}, {:.2}, {:.2}), player_obj_dist={:.2}m, dist_factor={:.2}, cam_dist={:.2}m", 
                       obj_x, obj_y, obj_z, player_pos.x, player_pos.y, player_pos.z, midpoint.x, midpoint.y, midpoint.z, smoothed_focus.x, smoothed_focus.y, smoothed_focus.z, player_object_distance, distance_factor, adjusted_camera_distance);
                
                // Calculate camera position using adjusted distance from the SMOOTHED focus
                let x = adjusted_camera_distance * orbit_cam.phi.sin() * orbit_cam.theta.cos();
                let y = adjusted_camera_distance * orbit_cam.phi.cos();
                let z = adjusted_camera_distance * orbit_cam.phi.sin() * orbit_cam.theta.sin();
                
                let camera_pos = smoothed_focus + glm::vec3(x, y, z);
                
                (smoothed_focus, camera_pos)
            } else {
                debug!("[CAMERA_FOCUS] No object position available, using player position");
                // Fallback to player position if object position unavailable
                let focus = smooth_focus;
                let camera_pos = orbit_cam.get_immediate_camera_position(focus);
                (focus, camera_pos)
            };
            
            let mut new_pos = adjusted_camera_pos;
            
            // Clamp camera Y so it never goes below the starting height during magnesis
            if let Ok(min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
                if let Some(min_y) = *min_lock {
                    if new_pos.y < min_y {
                        new_pos.y = min_y;
                    }
                }
            }
            
            // Update camera position with calculated focus
            self.pos = new_pos.into();
            self.focus = final_focus.into(); // Focus follows magnesis object position

            // Calculate rotation (up vector) using final focus for stable orientation
            let up = glm::vec3(0.0, 1.0, 0.0);
            let forward = glm::normalize(&(final_focus - new_pos));
            let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
            let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
            
            self.rot = camera_up.into();
            
            // Route mouse input to magnesis control as well
            let wheel_delta = input.zoom; // Use zoom input as wheel delta
            magnesis_experimental::update_magnesis_position(
                input.orbit_x, 
                input.orbit_y, 
                wheel_delta,
                crate::utils::get_global_config().magnesis_sensitivity
            );
            
            return;
        }

        // Normal camera mode - Apply rotation instantly with ZERO latency
        orbit_cam.update_orbit(input.orbit_x, input.orbit_y, input.zoom);

        // Get current target position (raw, no smoothing for rotation calculation)
        let target_pos = match link_position {
            Some(mut pos) => {
                // Add Y-offset to focus on Link's torso instead of feet (like game camera)
                pos.y += 1.8; // Approximate torso height offset in meters
                pos
            }
            None => {
                // Fallback to camera focus point
                self.focus.into()
            }
        };

        // Update smooth player position (ONLY for smooth following, not for camera rotation)
        orbit_cam.smooth_position_update(target_pos);

        // HYBRID APPROACH for best of both worlds:
        // - Use smooth position for gradual camera movement (eliminates jitter)
        // - But apply mouse rotation immediately on top of smooth position (zero latency)
        let smooth_focus = orbit_cam.smooth_player_pos; // Smooth following (player torso)
        let mut new_pos = orbit_cam.get_immediate_camera_position(smooth_focus);
        
        // Determine final focus:
        // - Normal mode: focus the player (smooth_focus)
        // - PhoneCamera mode: focus AHEAD along the current view direction so we keep looking forward
        let final_focus = if orbit_cam.phonecamera_zoom_active {
            // Direction from player toward the camera position (when distance is negative, this is the desired view dir)
            let dir_forward = glm::normalize(&(new_pos - smooth_focus)); // away from player, forward into the scene
            // Choose a focus distance ahead of the camera based on current zoom magnitude
            let ahead_dist = orbit_cam.distance.abs().max(5.0) + 10.0; // keep looking ahead sufficiently far
            new_pos + dir_forward * ahead_dist
        } else {
            smooth_focus
        };
        
        // Update camera position and focus (normal mode still respects any existing magnesis floor)
        if let Ok(min_lock) = MAGNESIS_CAMERA_MIN_Y.lock() {
            if let Some(min_y) = *min_lock {
                if new_pos.y < min_y { new_pos.y = min_y; }
            }
        }
        self.pos = new_pos.into();
        self.focus = final_focus.into();
        
        // Calculate rotation (up vector) using final focus for stable orientation
        let up = glm::vec3(0.0, 1.0, 0.0);
        let forward = glm::normalize(&(final_focus - new_pos));
        let right = glm::normalize(&glm::cross::<f32, glm::U3>(&forward, &up));
        let camera_up = glm::cross::<f32, glm::U3>(&right, &forward);
        
        self.rot = camera_up.into();
    }

}
