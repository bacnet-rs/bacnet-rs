use std::sync::{Arc, RwLock};

use super::{StateText, StateTextError, StateTextMut};

pub struct SyncStateText {
    reference_number: u32,
    texts: Vec<Arc<RwLock<String>>>,
}

impl StateText for &SyncStateText {
    fn get_text(self, index: usize) -> Result<String, StateTextError> {
        self.texts
            .get(index)
            .ok_or(StateTextError::OutOfRange)
            .and_then(|arc| {
                arc.read()
                    .map(|guard| guard.clone())
                    .map_err(|_| StateTextError::OutOfRange)
            })
    }

    fn number_of_states(self) -> u32 {
        self.texts.len() as u32
    }
}

impl StateText for &mut SyncStateText {
    fn get_text(self, index: usize) -> Result<String, StateTextError> {
        self.texts
            .get(index)
            .ok_or(StateTextError::OutOfRange)
            .and_then(|arc| {
                arc.read()
                    .map(|guard| guard.clone())
                    .map_err(|_| StateTextError::OutOfRange)
            })
    }

    fn number_of_states(self) -> u32 {
        self.texts.len() as u32
    }
}

impl StateTextMut for &mut SyncStateText {
    fn append_text(self, text: String) -> Result<usize, StateTextError> {
        self.texts.push(Arc::new(RwLock::new(text)));
        Ok(self.texts.len())
    }

    fn pop_text(self) -> Result<Option<String>, StateTextError> {
        Ok(self.texts.pop().and_then(|arc| {
            Arc::try_unwrap(arc)
                .ok()
                .map(|lock| lock.into_inner().unwrap())
        }))
    }

    fn set_state(self, index: u32, text: String) -> Result<Option<String>, StateTextError> {
        self.texts
            .get_mut(index as usize)
            .ok_or(StateTextError::OutOfRange)
            .and_then(|arc| {
                arc.write()
                    .map(|mut guard| Some(std::mem::replace(&mut *guard, text)))
                    .map_err(|_| StateTextError::OutOfRange)
            })
    }
}

impl StateText for &Arc<RwLock<SyncStateText>> {
    fn get_text(self, index: usize) -> Result<String, StateTextError> {
        self.read()
            .map_err(|_| StateTextError::OutOfRange)
            .and_then(|guard| {
                guard
                    .texts
                    .get(index)
                    .ok_or(StateTextError::OutOfRange)
                    .and_then(|arc| {
                        arc.read()
                            .map(|text_guard| text_guard.clone())
                            .map_err(|_| StateTextError::OutOfRange)
                    })
            })
    }

    fn number_of_states(self) -> u32 {
        self.read()
            .map(|guard| guard.texts.len() as u32)
            .unwrap_or(0)
    }
}

impl StateTextMut for &Arc<RwLock<SyncStateText>> {
    fn append_text(self, text: String) -> Result<usize, StateTextError> {
        self.write()
            .map_err(|_| StateTextError::OutOfRange)
            .map(|mut guard| {
                guard.texts.push(Arc::new(RwLock::new(text)));
                guard.texts.len()
            })
    }

    fn pop_text(self) -> Result<Option<String>, StateTextError> {
        self.write()
            .map_err(|_| StateTextError::OutOfRange)
            .map(|mut guard| {
                guard.texts.pop().and_then(|arc| {
                    Arc::try_unwrap(arc)
                        .ok()
                        .map(|lock| lock.into_inner().unwrap())
                })
            })
    }

    fn set_state(self, index: u32, text: String) -> Result<Option<String>, StateTextError> {
        self.write()
            .map_err(|_| StateTextError::OutOfRange)
            .and_then(|mut guard| {
                guard
                    .texts
                    .get_mut(index as usize)
                    .ok_or(StateTextError::OutOfRange)
                    .and_then(|arc| {
                        arc.write()
                            .map(|mut text_guard| Some(std::mem::replace(&mut *text_guard, text)))
                            .map_err(|_| StateTextError::OutOfRange)
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::sync::{Arc, RwLock};

    use crate::object::{
        object_name::IntoBoxedObjectName, state_text::complex::SyncStateText, MultiStateInput,
    };

    #[test]
    #[ignore]
    fn smoke() -> Result<(), Box<dyn core::error::Error>> {
        let values: Vec<_> = ["normal", "alarm", "offline", "burned down"]
            .into_iter()
            .map(|x| Arc::new(RwLock::new(x.to_owned())))
            .collect();
        let states = Arc::new(RwLock::new(SyncStateText {
            reference_number: 2,
            texts: values,
        }));
        let obj = MultiStateInput::new(33, "test".into_object_name(), states.clone());
        let moved = states.clone();

        std::thread::spawn(move || {
            // loops with interval and updates values
            let total = { moved.read().unwrap().texts.len() };
            // avoids holding the lock
            for _ in 0..(60 * 60) {
                for i in 0..total {
                    {
                        let guard = moved.read().unwrap();
                        let mut guard = guard.texts[i].write().unwrap();
                        *guard += "a";
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        });

        for _ in 0..(60 * 30) {
            for text in &obj.state_text.read().unwrap().texts {
                let v = text.read().unwrap();
                println!("Text: {v}");
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        std::thread::spawn(|| {
            drop(obj);
        });

        Ok(())
    }
}
