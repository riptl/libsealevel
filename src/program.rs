use {
    crate::{
        config::sealevel_config, context::sealevel_syscall_registry, error::hoist_error,
        vm::ThisInstructionMeter,
    },
    solana_bpf_loader_program::BpfError,
    solana_rbpf::{
        elf::Executable,
        verifier::RequisiteVerifier,
        vm::{Config, SyscallRegistry, VerifiedExecutable},
    },
    std::{os::raw::c_char, ptr::null_mut},
};

/// A loaded and relocated program.
///
/// To execute this program, create a VM with `sealevel_vm_create`.
pub struct sealevel_executable {
    pub(crate) program: VerifiedExecutable<RequisiteVerifier, BpfError, ThisInstructionMeter>,
    pub(crate) is_jit_compiled: bool,
}

/// Access parameters of an account usage in an instruction.
#[repr(C)]
pub struct sealevel_instruction_account {
    pub index_in_transaction: usize,
    pub index_in_caller: usize,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Loads a Sealevel program from an ELF buffer and verifies its SBF bytecode.
///
/// Sets `sealevel_errno` and returns a null pointer if loading failed.
///
/// Syscalls and config may be null pointers, in which case defaults are used.
/// These defaults is not stable across any libsealevel versions.
///
/// If a syscall registry is provided, it is consumed, and cannot be used a second time.
///
/// # Safety
/// Avoid the following undefined behavior:
/// - Using the syscalls object parameter after calling this function (including a second call of this function).
/// - Providing a config object that has been freed with `sealevel_config_free` before.
#[no_mangle]
pub unsafe extern "C" fn sealevel_load_program(
    config: *const sealevel_config,
    syscalls: sealevel_syscall_registry,
    data: *const c_char,
    data_len: usize,
) -> *mut sealevel_executable {
    let data_slice = std::slice::from_raw_parts(data as *const u8, data_len);
    let config = if config.is_null() {
        Config::default()
    } else {
        (*config).config
    };
    let syscalls = if syscalls.0.is_null() {
        SyscallRegistry::default()
    } else {
        syscalls.take().unwrap() // TODO set error code
    };
    let load_result =
        Executable::<BpfError, ThisInstructionMeter>::from_elf(data_slice, config, syscalls);
    let executable = match hoist_error(load_result) {
        None => return null_mut(),
        Some(v) => v,
    };
    let verify_result = VerifiedExecutable::from_executable(executable);
    match hoist_error(verify_result) {
        None => null_mut(),
        Some(program) => {
            let wrapper = sealevel_executable {
                program,
                is_jit_compiled: false,
            };
            Box::into_raw(Box::new(wrapper))
        }
    }
}

/// Compiles a program to native executable code.
///
/// Sets `sealevel_errno`.
///
/// # Safety
/// Avoid the following undefined behavior:
/// - Calling this function twice on the same program.
/// - Calling this function given a null pointer or an invalid pointer.
#[no_mangle]
pub unsafe extern "C" fn sealevel_program_jit_compile(program: *mut sealevel_executable) {
    let result = (*program).program.jit_compile();
    if hoist_error(result).is_some() {
        (*program).is_jit_compiled = true;
    }
}
