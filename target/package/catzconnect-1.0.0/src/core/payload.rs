use crate::{
    error::CatzError,
    types::{Channel, MessageType, SendInput, Template},
    utils::validators::validate_email,
};

pub fn verify_payload(input: &SendInput) -> Result<(), CatzError> {
    match (&input.channel, &input.message_type, &input.template) {
        (Channel::Email, MessageType::Verification, Template::Otp) => {
            let to = input
                .payload
                .to
                .as_deref()
                .ok_or_else(|| CatzError::Validation("Missing 'to' in payload".into()))?;

            if input.payload.otp.is_none() {
                return Err(CatzError::Validation("Missing 'otp' in payload".into()));
            }

            validate_email(to)?;

            Ok(())
        }
    }
}
