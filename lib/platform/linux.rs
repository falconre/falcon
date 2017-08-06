use il;
use std::collections::BTreeMap;


#[derive(Clone)]
pub struct Linux {
    files: BTreeMap<i32, File>,
    next_fd: i32,
    symbolic_variables: Vec<il::Scalar>
}


impl Linux {
    pub fn new() -> Linux {
        Linux {
            files: BTreeMap::new(),
            next_fd: 0,
            symbolic_variables: Vec::new()
        }
    }


    pub fn symbolic_variables(&self) -> &Vec<il::Scalar> {
        &self.symbolic_variables
    }


    pub fn open(&mut self, filename: &str, permissions: u32) -> i32 {
        let fd = self.next_fd;
        self.files.insert(fd,
            File::new(FileDescriptor::new(fd), filename.to_owned()));

        self.next_fd += 1;

        fd
    }


    pub fn read(&mut self, fd: i32, mut length: u64) -> (i32, Vec<il::Scalar>) {
        if let Some(file) = self.files.get_mut(&fd) {
            if length > 4096 {
                length = 4096;
            }
            let v = file.file_descriptor_mut().read(length);
            self.symbolic_variables.append(&mut v.clone());
            return (v.len() as i32, v);
        }
        else {
            return (-9, Vec::new())
        }
    }
}


#[derive(Clone)]
pub struct FileDescriptor {
    fd: i32,
    offset: u64
}


impl FileDescriptor {
    /// Create a new file descriptor
    pub fn new(fd: i32) -> FileDescriptor {
        FileDescriptor {
            fd: fd,
            offset: 0
        }
    }


    /// Seek to a given offset in the file descriptor
    pub fn seek(&mut self, offset: u64) {
        self.offset = offset
    }


    /// Simulate a read over the file descriptor, returning a vector of
    /// il::Scalar for each byte read.
    pub fn read(&mut self, length: u64) -> Vec<il::Scalar> {
        let mut v = Vec::new();
        for _ in 0..length {
            v.push(il::scalar(format!("fd_{}_{}", self.fd, self.offset), 8));
            self.offset += 1;
        }
        v
    }

}


#[derive(Clone)]
pub struct File {
    file_descriptor: FileDescriptor,
    filename: String
}


impl File {
    pub fn new(file_descriptor: FileDescriptor, filename: String) -> File {
        File{
            file_descriptor: file_descriptor,
            filename: filename
        }
    }


    pub fn filename(&self) -> &str {
        &self.filename
    }


    pub fn file_descriptor(&self) -> &FileDescriptor {
        &self.file_descriptor
    }


    pub fn file_descriptor_mut(&mut self) -> &mut FileDescriptor {
        &mut self.file_descriptor
    }
}