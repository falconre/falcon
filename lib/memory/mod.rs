pub mod backing;
pub mod paged;
pub mod value;


bitflags! {
    /// RWX permissions for memory.
    #[derive(Deserialize, Serialize)]
    pub struct MemoryPermissions: u32 {
        const NONE    = 0b000;
        const READ    = 0b001;
        const WRITE   = 0b010;
        const EXECUTE = 0b100;
        const ALL     = 0b111;
    }
}