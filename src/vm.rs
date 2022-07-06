use {
    crate::{error::hoist_error, program::sealevel_executable},
    solana_bpf_loader_program::BpfError,
    solana_program_runtime::invoke_context::ComputeMeter,
    solana_rbpf::{
        memory_region::MemoryRegion,
        verifier::RequisiteVerifier,
        vm::{EbpfVm, InstructionMeter},
    },
    std::{cell::RefCell, ffi::c_void, os::raw::c_int, ptr::null_mut, rc::Rc, slice},
};

pub struct sealevel_vm {
    pub(crate) vm: EbpfVm<'static, RequisiteVerifier, BpfError, ThisInstructionMeter>, // hack: lifetime is not static
    pub(crate) program: *const sealevel_executable,
}

#[repr(C)]
pub struct sealevel_region {
    pub data_addr: *mut c_void,
    pub data_size: usize,
    pub vm_addr: u64,
    pub vm_gap_size: u64,
    pub is_writable: bool,
}

unsafe fn create_region(r: &sealevel_region) -> MemoryRegion {
    let slice = slice::from_raw_parts_mut(r.data_addr as *mut u8, r.data_size);
    // TODO don't call testing func in prod :)
    MemoryRegion::new_for_testing(slice, r.vm_addr, r.vm_gap_size, r.is_writable)
}

/// Creates a Sealevel virtual machine and loads the given program into it.
///
/// Sets `sealevel_errno` and returns a null pointer if loading failed.
///
/// The given heap should be 16-byte aligned.
///
/// # Safety
/// Avoid the following undefined behavior:
/// - Destroying the program, heap, or regions before calling sealevel_vm_destroy.
/// - Sharing the same heap or memory regions across multiple threads.
#[no_mangle]
pub unsafe extern "C" fn sealevel_vm_create(
    program: *const sealevel_executable,
    heap_ptr: *mut u8,
    heap_len: usize,
    regions_ptr: *const sealevel_region,
    regions_count: c_int,
) -> *mut sealevel_vm {
    let heap_ptr = heap_ptr as *mut u8;
    let heap_slice = slice::from_raw_parts_mut(heap_ptr, heap_len);

    let raw_regions = slice::from_raw_parts(regions_ptr, regions_count as usize);
    let regions = raw_regions.iter().map(|r| create_region(r)).collect();

    let result = EbpfVm::new(&((*program).program), heap_slice, regions);
    match hoist_error(result) {
        None => null_mut(),
        Some(vm) => {
            let wrapper = sealevel_vm { vm, program };
            Box::into_raw(Box::new(wrapper))
        }
    }
}

/// Release a virtual machine and its execution state.
///
/// # Safety
/// Avoid the following undefined behavior:
/// - Invoking this function twice on the same VM
#[no_mangle]
pub unsafe extern "C" fn sealevel_vm_destroy(vm: *mut sealevel_vm) {
    if vm.is_null() {
        return;
    }
    drop(Box::from_raw(vm))
}

/// Executes a Sealevel virtual machine.
///
/// # Safety
/// Avoid the following undefined behavior:
/// - Passing a null pointer argument
/// - Invoking the same program twice
#[no_mangle]
pub unsafe extern "C" fn sealevel_vm_execute(vm: *mut sealevel_vm) -> u64 {
    // TODO Configurable instruction meter
    let mut instruction_meter = ThisInstructionMeter::new(ComputeMeter::new_ref(100000));
    let result = if (*(*vm).program).is_jit_compiled {
        (*vm).vm.execute_program_jit(&mut instruction_meter)
    } else {
        (*vm).vm.execute_program_interpreted(&mut instruction_meter)
    };
    let ret_opt = hoist_error(result);
    ret_opt.unwrap_or(0u64)
}

/// Passed to the VM to enforce the compute budget
pub struct ThisInstructionMeter {
    pub compute_meter: Rc<RefCell<ComputeMeter>>,
}

impl ThisInstructionMeter {
    pub fn new(compute_meter: Rc<RefCell<ComputeMeter>>) -> Self {
        Self { compute_meter }
    }
}

impl InstructionMeter for ThisInstructionMeter {
    fn consume(&mut self, amount: u64) {
        // 1 to 1 instruction to compute unit mapping
        // ignore error, Ebpf will bail if exceeded
        let _ = self.compute_meter.borrow_mut().consume(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.compute_meter.borrow().get_remaining()
    }
}
