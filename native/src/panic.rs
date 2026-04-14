// Thread-local error message for the last failed operation
thread_local! {
    static LAST_ERROR: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

#[no_mangle]
pub extern "C" fn jerboa_last_error(buf: *mut u8, buf_len: usize) -> usize {
    LAST_ERROR.with(|e| {
        let msg = e.borrow();
        let bytes = msg.as_bytes();
        let copy_len = bytes.len().min(buf_len.saturating_sub(1));
        if !buf.is_null() && copy_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
                *buf.add(copy_len) = 0;
            }
        }
        bytes.len()
    })
}

pub fn set_last_error(msg: String) {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = msg);
}
