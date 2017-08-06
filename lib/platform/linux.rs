//! A model of the Linux Operating System.

use il;
use std::collections::BTreeMap;

/// A model of the Linux Operating System.
#[derive(Clone)]
pub struct Linux {
    files: BTreeMap<i32, File>,
    next_fd: i32,
    symbolic_variables: Vec<il::Scalar>
}


impl Linux {
    /// Create a new `Linux` model.
    pub fn new() -> Linux {
        Linux {
            files: BTreeMap::new(),
            next_fd: 0,
            symbolic_variables: Vec::new()
        }
    }

    /// Get all symbolic variables that have been produced by this instance of `Linux`.
    pub fn symbolic_variables(&self) -> &Vec<il::Scalar> {
        &self.symbolic_variables
    }

    /// Open a file.
    pub fn open(&mut self, filename: &str) -> i32 {
        let fd = self.next_fd;
        self.files.insert(fd,
            File::new(FileDescriptor::new(fd), filename.to_owned()));

        self.next_fd += 1;

        fd
    }

    /// Read from an open file descriptor.
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
struct FileDescriptor {
    fd: i32,
    offset: u64
}


impl FileDescriptor {
    /// Create a new file descriptor
    fn new(fd: i32) -> FileDescriptor {
        FileDescriptor {
            fd: fd,
            offset: 0
        }
    }


    /// Simulate a read over the file descriptor, returning a vector of
    /// il::Scalar for each byte read.
    fn read(&mut self, length: u64) -> Vec<il::Scalar> {
        let mut v = Vec::new();
        for _ in 0..length {
            v.push(il::scalar(format!("fd_{}_{}", self.fd, self.offset), 8));
            self.offset += 1;
        }
        v
    }

}


#[derive(Clone)]
struct File {
    file_descriptor: FileDescriptor,
    filename: String
}


impl File {
    fn new(file_descriptor: FileDescriptor, filename: String) -> File {
        File{
            file_descriptor: file_descriptor,
            filename: filename
        }
    }


    fn file_descriptor_mut(&mut self) -> &mut FileDescriptor {
        &mut self.file_descriptor
    }
}