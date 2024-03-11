const Joi = require('joi');

// validation schema for user registration
const validateUser = Joi.object({
  username: Joi.string().alphanum().min(3).max(30),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .max(40)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+{}|:"<>?~`\-=[\]\\;',./]).{8,40}$/,
    )
    .message(
      '"{#label}" must contain at least 1 lowercase letter, 1 uppercase letter, 1 number, 1 symbol, and be 8-40 characters.',
    )
    .required(),
  profilePicUrl: Joi.string(),
  bio: Joi.string(),
});

// validate schema for user login
const validateLogin = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .max(40)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+{}|:"<>?~`\-=[\]\\;',./]).{8,40}$/,
    )
    .message(
      '"{#label}" must contain at least 1 lowercase letter, 1 uppercase letter, 1 number, 1 symbol, and be 8-40 characters.',
    )
    .required(),
});

module.exports = {
  validateUser,
  validateLogin,
};
