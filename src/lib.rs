use cryptoxide::chacha20;
use cryptoxide::chacha20poly1305::{self, Context, ContextDecryption, ContextEncryption};
use cryptoxide::kdf::argon2;
use getrandom::getrandom;
use std::fs::File;
use std::io::{Read, Write};
use thiserror::Error;

pub const ENIGFILE_HEADER: &[u8; 8] = b"ENIGFILE";
pub const CHUNK_SIZE: usize = 8 * 1024 * 1024;

pub trait Reporter {
    /// call this callback with the number of bytes read from the input
    /// and the current chunk number
    fn chunk_start(&self, data_read: u64, chunk_number: usize) -> ();
}

pub struct ReporterNone;

impl Reporter for ReporterNone {
    fn chunk_start(&self, _data_read: u64, _chunk_number: usize) {}
}

pub enum EitherReport<R1: Reporter, R2: Reporter> {
    Right(R1),
    Left(R2),
}

impl<R1: Reporter, R2: Reporter> EitherReport<R1, R2> {
    pub fn right(r1: R1) -> Self {
        EitherReport::Right(r1)
    }

    pub fn left(r2: R2) -> Self {
        EitherReport::Left(r2)
    }
}

impl<R1: Reporter, R2: Reporter> Reporter for EitherReport<R1, R2> {
    fn chunk_start(&self, data_read: u64, chunk_number: usize) {
        match self {
            EitherReport::Right(r1) => r1.chunk_start(data_read, chunk_number),
            EitherReport::Left(r2) => r2.chunk_start(data_read, chunk_number),
        }
    }
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("I/O Error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Chunk data too big: {size}")]
    ChunkDataTooBig { size: usize },
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Invalid Magic={magic:?}")]
    InvalidMagic { magic: [u8; 8] },
    #[error("Invalid Version Header byte={header_byte}")]
    InvalidVersionField { header_byte: u8 },
    #[error("Invalid Header Field")]
    InvalidHeaderFields,
    #[error("Invalid Version byte={version_byte}")]
    InvalidVersion { version_byte: u8 },
    #[error("Read I/O Error at Header: {err}")]
    ReaderHeaderIO { err: std::io::Error },
    #[error("Read I/O Error: {err} at (chunk_number={chunk_number}")]
    ReadIO {
        chunk_number: usize,
        err: std::io::Error,
    },
    #[error("Write I/O Error: {err} at offset: {offset}")]
    WriteIO { offset: usize, err: std::io::Error },
    #[error("Chunk data too big: {size}")]
    ChunkDataTooBig { size: usize },
    #[error("Mismatch authentication, data has been tempered or key is incorrect")]
    MismatchTag,
}

#[derive(Clone, Copy, Debug)]
pub enum Version {
    V1,
}

impl Version {
    fn as_byte(self) -> u8 {
        match self {
            Version::V1 => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Parameters {
    version: Version,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            version: Version::V1,
        }
    }
}

const CHUNK_ALIGNMENT: usize = 4;

/// Encryption context
pub struct RootContext(chacha20::ChaCha<20>);

impl RootContext {
    fn new_dec(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self(chacha20::ChaCha::new(key, nonce))
    }

    pub fn new(keyn: &[u8; 44]) -> Self {
        // unwrap is safe here since we expect a fixed sized of 44 (32 + 12)
        let key = keyn[0..32].try_into().unwrap();
        let nonce = keyn[32..44].try_into().unwrap();
        Self::new_dec(key, nonce)
    }

    pub fn econtext(&mut self) -> EContext {
        let mut e = [0u8; 44];
        self.0.process_mut(&mut e);
        let ctx = Context::new(&e[0..32], &e[32..44]);
        ctx.to_encryption()
    }

    pub fn dcontext(&mut self) -> DContext {
        let mut e = [0u8; 44];
        self.0.process_mut(&mut e);
        let ctx = Context::new(&e[0..32], &e[32..44]);
        ctx.to_decryption()
    }
}

/// Encryption context
pub type EContext = ContextEncryption<20>;

/// Decryption context
pub type DContext = ContextDecryption<20>;

/// Write a chunk of data by encrypting it first, and prepending a chunk length (32 bits)
/// and the authenticated tag
///
/// the data is also 4-byte aligned for the next chunk (irrespective if there's more chunk of data after)
fn encrypt_and_output<W: Write>(
    mut ctx: EContext,
    output: &mut W,
    data: &mut [u8],
) -> Result<(), EncryptionError> {
    const ALIGNED: [u8; 4] = [0, 0, 0, 0];

    if data.len() > CHUNK_SIZE {
        return Err(EncryptionError::ChunkDataTooBig { size: data.len() });
    }

    let unaligned = data.len() % CHUNK_ALIGNMENT;

    ctx.encrypt_mut(data);
    let tag = ctx.finalize();

    // create a 4 + 16 bytes overhead per chunk
    output.write_all(&u32::to_be_bytes(data.len() as u32))?;
    output.write_all(&tag.0)?;

    // then write the data, aligned with an optional 4-bytes boundary (of zeroes)
    output.write_all(&data)?;
    if unaligned > 0 {
        output.write_all(&ALIGNED[0..(CHUNK_ALIGNMENT - unaligned)])?;
    }
    Ok(())
}

fn decrypt_and_output<W: Write>(
    mut ctx: DContext,
    data: &mut [u8],
    tag: &[u8; 16],
    offset: usize,
    output: &mut W,
) -> Result<(), DecryptionError> {
    if data.len() > CHUNK_SIZE {
        return Err(DecryptionError::ChunkDataTooBig { size: data.len() });
    }

    let read_tag = chacha20poly1305::Tag(tag.clone());

    ctx.decrypt_mut(data);
    if ctx.finalize(&read_tag) == chacha20poly1305::DecryptionResult::MisMatch {
        Err(DecryptionError::MismatchTag)
    } else {
        output
            .write_all(&data)
            .map_err(|err| DecryptionError::WriteIO { offset, err })?;
        Ok(())
    }
}

pub fn encrypt_stream_inner<I: Reporter, R: Read, W: Write>(
    report: &I,
    root_ctx: &mut RootContext,
    r: &mut R,
    w: &mut W,
) -> Result<(), EncryptionError> {
    let mut buf = vec![0; CHUNK_SIZE];
    let mut ofs = 0;

    let mut chunk = 0;
    let mut data_read = 0u64;

    loop {
        if ofs == 0 {
            report.chunk_start(data_read, chunk);
        }

        let sz = r.read(&mut buf[ofs..])?;
        ofs += sz;
        data_read += sz as u64;

        if sz == 0 {
            // reach end of file, so just wrap what we have to file (if anything)
            if ofs > 0 {
                let ctx = root_ctx.econtext();
                encrypt_and_output(ctx, w, &mut buf[0..ofs])?;
            }
            return Ok(());
        } else if ofs == CHUNK_SIZE {
            let ctx = root_ctx.econtext();
            encrypt_and_output(ctx, w, &mut buf[0..ofs])?;
            ofs = 0;
            chunk += 1;
        }
    }
}

fn read_exact_or_eof<R: Read>(r: &mut R, output: &mut [u8]) -> Option<std::io::Result<()>> {
    let mut ofs = 0;
    loop {
        match r.read(&mut output[ofs..]) {
            Err(e) => return Some(Err(e)),
            Ok(0) => {
                if ofs == 0 {
                    return None;
                }
            }
            Ok(sz) => {
                ofs += sz;
                if ofs == output.len() {
                    return Some(Ok(()));
                }
            }
        }
    }
    //
}

fn decrypt_stream_inner<I: Reporter, R: Read, W: Write>(
    report: &I,
    root_ctx: &mut RootContext,
    r: &mut R,
    w: &mut W,
) -> Result<(), DecryptionError> {
    let mut chunk_header = [0u8; 20];
    let mut buf = vec![0; CHUNK_SIZE];

    let mut chunk_number = 0;
    let mut output_offset = 0;

    let mut data_read = 0u64;

    loop {
        // read the chunk header
        match read_exact_or_eof(r, &mut chunk_header) {
            None => return Ok(()),
            Some(Err(e)) => {
                return Err(DecryptionError::ReadIO {
                    chunk_number,
                    err: e,
                });
            }
            Some(Ok(())) => {}
        }

        report.chunk_start(data_read, chunk_number);

        // unwrap as we know there's 4 bytes in 20 bytes
        let len_chunk = u32::from_be_bytes(chunk_header[0..4].try_into().unwrap()) as usize;
        if len_chunk > CHUNK_SIZE {
            return Err(DecryptionError::ChunkDataTooBig { size: len_chunk });
        }
        let tag = chunk_header[4..20].try_into().unwrap();

        let read_length = if len_chunk % CHUNK_ALIGNMENT != 0 {
            len_chunk + CHUNK_ALIGNMENT - (len_chunk % CHUNK_ALIGNMENT)
        } else {
            len_chunk
        };

        // read the encrypted data
        r.read_exact(&mut buf[0..read_length])
            .map_err(|e| DecryptionError::ReadIO {
                chunk_number,
                err: e,
            })?;
        data_read += read_length as u64;

        let ctx = root_ctx.dcontext();
        let data = &mut buf[0..len_chunk];
        decrypt_and_output(ctx, data, tag, output_offset, w)?;
        output_offset += data.len();

        chunk_number += 1;
    }
}

fn context_init(
    parameters: &Parameters,
    symkey: &[u8],
    password: &[u8],
    random: &[u8; 16],
) -> RootContext {
    match parameters.version {
        Version::V1 => {
            // the parameter are explicitely listed so that we are resilient to any future (unlikely) default change
            let params = argon2::Params::argon2d()
                .memory_kb(128)
                .expect("valid memory configuration")
                .parallelism(1)
                .expect("valid parallelism configuration")
                .iterations(4)
                .expect("valid iteration configuration");
            let output = argon2::argon2::<44>(&params, password, random, symkey, b"");

            RootContext::new(&output)
        }
    }
}

/// Encrypt the input read stream into the output write sink using the given password
///
/// Note that the random is explicitely given to this function, to allow deterministic
/// data for certain cases, but it's important that the given random is randomly generated
fn encrypt_stream<I: Reporter, R: Read, W: Write>(
    report: &I,
    parameters: Parameters,
    password: &[u8],
    random: &[u8; 16],
    r: &mut R,
    w: &mut W,
) -> Result<(), EncryptionError> {
    // header is 40 bytes;
    // 8 bytes MAGIC
    // 1 byte VERSION, with is serialized at byte + 0x30, anything under is invalid.
    // 15 bytes zeroes (for future extensibility and configuration)
    // 16 bytes random
    let mut header = [0u8; 40];

    let version: u8 = 0x30 + parameters.version.as_byte(); // adding 0x30 so that it starts at ASCII character 0
    let flags: u64 = (version as u64) << 56 | 0;

    header[0..8].copy_from_slice(ENIGFILE_HEADER);
    header[8..16].copy_from_slice(&flags.to_be_bytes());
    header[16..24].copy_from_slice(&0u64.to_be_bytes());
    header[24..40].copy_from_slice(random);

    w.write_all(&header)?;

    let mut root_ctx = context_init(&parameters, &[], password, random);

    encrypt_stream_inner(report, &mut root_ctx, r, w)?;

    Ok(())
}

/// Encrypt a file into another file, using the given password
///
/// Note that the output file is not deterministic here, as we get the system random
/// to initialize the cryptographic primitives. use `encrypt_stream` for a
/// deterministic construction
pub fn encrypt_file<I: Reporter>(
    report: &I,
    password: &[u8],
    input: &mut File,
    output: &mut File,
) -> Result<(), EncryptionError> {
    let mut random = [0; 16];
    getrandom(&mut random).unwrap();

    let params = Parameters::default();
    encrypt_stream(report, params, password, &random, input, output)
}

/// Decrypt the input read stream into the output write sink using the given password
pub fn decrypt_stream<I: Reporter, R: Read, W: Write>(
    report: &I,
    password: &[u8],
    input: &mut R,
    output: &mut W,
) -> Result<(), DecryptionError> {
    let mut header = [0u8; 40];

    input
        .read_exact(&mut header)
        .map_err(|err| DecryptionError::ReaderHeaderIO { err })?;

    if &header[0..8] != ENIGFILE_HEADER {
        return Err(DecryptionError::InvalidMagic {
            magic: <&[u8; 8]>::try_from(&header[0..8]).unwrap().clone(),
        });
    }

    if header[8] < 0x30 {
        return Err(DecryptionError::InvalidVersionField {
            header_byte: header[8],
        });
    }
    let ver = header[8] - 0x30;
    let version = if ver == 0 {
        Version::V1
    } else {
        return Err(DecryptionError::InvalidVersion { version_byte: ver });
    };

    if header[9..24].iter().any(|v| *v != 0) {
        return Err(DecryptionError::InvalidHeaderFields);
    }

    let random = header[24..40].try_into().unwrap();

    let mut params = Parameters::default();
    params.version = version;

    let mut root_ctx = context_init(&params, &[], password, random);

    decrypt_stream_inner(report, &mut root_ctx, input, output)?;

    Ok(())
}

/// Decrypt a file into a new file, using the given password
pub fn decrypt_file<I: Reporter>(
    report: &I,
    password: &[u8],
    input: &mut File,
    output: &mut File,
) -> Result<(), DecryptionError> {
    decrypt_stream(report, password, input, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize() {
        // 2 chunks + partial chunk
        let input = vec![1u8; 20 * 1024 * 1024 + 13];
        let mut output = Vec::new();
        let mut decrypted = Vec::new();

        let parameters = Parameters::default();

        let password = b"password";

        encrypt_stream(
            &ReporterNone,
            parameters,
            password,
            &[0xff; 16],
            &mut &input[..],
            &mut output,
        )
        .expect("encryption works");

        decrypt_stream(&ReporterNone, password, &mut &output[..], &mut decrypted)
            .expect("decryption works");

        assert_eq!(input, decrypted);
    }

    #[test]
    fn serialize_1byte() {
        let mut output = vec![];
        let parameters = Parameters::default();
        let input = vec![0x29];

        let password = b"password";

        encrypt_stream(
            &ReporterNone,
            parameters,
            password,
            &[0xff; 16],
            &mut &input[..],
            &mut output,
        )
        .expect("encryption works");

        assert_eq!(
            output,
            &[
                69, 78, 73, 71, 70, 73, 76, 69, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,
                0, 0, 1, 10, 248, 101, 89, 51, 92, 69, 129, 141, 151, 19, 78, 221, 144, 203, 179,
                113, 0, 0, 0
            ]
        );
    }
}
