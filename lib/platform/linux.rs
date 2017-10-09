//! A model of the Linux Operating System.

use il;
use RC;
use std::collections::BTreeMap;

/// A model of the Linux Operating System.
#[derive(Clone)]
pub struct Linux {
    files: BTreeMap<String, RC<File>>,
    file_descriptors: BTreeMap<i32, FileDescriptor>,
    next_fd: i32,
    symbolic_scalars: Vec<il::Scalar>
}


impl Linux {
    /// Create a new `Linux` model.
    pub fn new() -> Linux {
        Linux {
            files: BTreeMap::new(),
            file_descriptors: BTreeMap::new(),
            next_fd: 0,
            symbolic_scalars: Vec::new()
        }
    }

    /// Get all symbolic variables that have been produced by this instance of `Linux`.
    pub fn symbolic_scalars(&self) -> &Vec<il::Scalar> {
        &self.symbolic_scalars
    }

    /// Open a file.
    pub fn open(&mut self, filename: &str) -> i32 {
        if self.files.get(filename).is_none() {
            let file = RC::new(File::new(filename.to_owned()));
            self.files.insert(filename.to_owned(), file);
        }

        let file = self.files.get(filename).unwrap();
        let file_descriptor = FileDescriptor::new(self.next_fd, file.clone());
        self.file_descriptors.insert(self.next_fd, file_descriptor);
        self.next_fd += 1;
        self.next_fd - 1
    }

    /// Read from an open file descriptor.
    pub fn read(&mut self, fd: i32, mut length: usize) -> (i32, Vec<il::Expression>) {
        if let Some(file_descriptor) = self.file_descriptors.get_mut(&fd) {
            if length > 4096 {
                length = 4096;
            }
            let mut file_read_result = file_descriptor.read(length);
            self.symbolic_scalars.append(&mut file_read_result.new_symbolic_scalars);
            (file_read_result.bytes.len() as i32, file_read_result.bytes)
        }
        else {
            (-9, Vec::new())
        }
    }

    /// Write to an open file descriptor
    pub fn write(&mut self, fd: i32, contents: Vec<il::Expression>) -> i32 {
        if let Some(file_descriptor) = self.file_descriptors.get_mut(&fd) {
            let length = contents.len();
            file_descriptor.write(contents);
            length as i32
        }
        else {
            -9
        }
    }
}


#[derive(Clone)]
struct FileDescriptor {
    fd: i32,
    offset: u64,
    // TODO: This should be more generic
    io: RC<File>
}


impl FileDescriptor {
    /// Create a new file descriptor
    fn new(fd: i32, io: RC<File>) -> FileDescriptor {
        FileDescriptor {
            fd: fd,
            offset: 0,
            io: io
        }
    }


    /// Simulate a read over the file descriptor, returning a vector of
    /// il::Scalar for each byte read.
    fn read(&mut self, length: usize) -> FileReadResult {
        let offset = self.offset;
        let result = RC::make_mut(&mut self.io).read(offset, length, self.fd);
        self.offset += length as u64;
        result
    }


    /// Simulate a write over the file descriptor
    fn write(&mut self, contents: Vec<il::Expression>) {
        RC::make_mut(&mut self.io).write(self.offset, contents);
    }
}



struct FileReadResult {
    bytes: Vec<il::Expression>,
    new_symbolic_scalars: Vec<il::Scalar>
}


trait IOHandle {
    /// Read from an I/O device, such as a `File` or a Socket
    fn read(&mut self, offset: u64, length: usize, fd: i32) -> FileReadResult;

    /// Write to an I/O device, such as a `File` or a Socket
    fn write(&mut self, offset: u64, contents: Vec<il::Expression>);
}


/// Model of a File in Linux
#[derive(Clone)]
struct File {
    filename: String,
    contents: BTreeMap<u64, il::Expression>
}


impl File {
    fn new(filename: String) -> File {
        File{
            filename: filename,
            contents: BTreeMap::new()
        }
    }
}


impl IOHandle for File {
    fn read(&mut self, offset: u64, length: usize, fd: i32) -> FileReadResult {
        let mut bytes = Vec::new();
        let mut new_symbolic_scalars = Vec::new();

        for i in offset..(offset + length as u64) {
            if let Some(expr) = self.contents.get(&i) {
                bytes.push(expr.clone());
            }
            else {
                let scalar = il::scalar(
                    format!("fd_{}_{}", fd, i),
                    8
                );
                bytes.push(scalar.clone().into());
                new_symbolic_scalars.push(scalar);
            }
        }

        FileReadResult {
            bytes: bytes,
            new_symbolic_scalars: new_symbolic_scalars
        }
    }


    fn write(&mut self, offset: u64, contents: Vec<il::Expression>) {
        let mut off = offset;
        for expr in contents {
            self.contents.insert(off, expr);
            off += 1;
        }
    }
}