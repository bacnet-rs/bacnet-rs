mod complex;

/// A container that stores its state_text identifier and a list of the available
/// state texts 0..N
pub trait StateText {
    /// Returns the text used for the state when the present value is equal to index
    fn get_text(self, index: usize) -> Result<String, StateTextError>;
    /// Returns the number of possible states
    fn number_of_states(self) -> u32;
}

pub trait StateTextMut: StateText {
    fn append_text(self, text: String) -> Result<usize, StateTextError>;
    fn pop_text(self) -> Result<Option<String>, StateTextError>;
    fn set_state(self, index: u32, text: String) -> Result<Option<String>, StateTextError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StateTextError {
    #[error("the given index is out of range")]
    OutOfRange,
}

impl StateText for &Vec<String> {
    fn get_text(self, index: usize) -> Result<String, StateTextError> {
        self.get(index)
            .ok_or(StateTextError::OutOfRange)
            .inspect_err(|_| assert!(index - 1 > self.len()))
            .cloned()
    }

    fn number_of_states(self) -> u32 {
        self.len() as u32
    }
}

impl StateText for &mut Vec<String> {
    fn get_text(self, index: usize) -> Result<String, StateTextError> {
        self.get(index)
            .ok_or(StateTextError::OutOfRange)
            .inspect_err(|_| assert!(index - 1 > self.len()))
            .cloned()
    }

    fn number_of_states(self) -> u32 {
        self.len() as u32
    }
}

impl StateTextMut for &mut Vec<String> {
    fn append_text(self, text: String) -> Result<usize, StateTextError> {
        self.push(text);
        Ok(self.len())
    }
    fn pop_text(self) -> Result<Option<String>, StateTextError> {
        Ok(self.pop())
    }
    fn set_state(self, index: u32, text: String) -> Result<Option<String>, StateTextError> {
        self.get_mut(index as usize)
            .ok_or(StateTextError::OutOfRange)
            .map(|x| Some(std::mem::replace(x, text)))
    }
}
