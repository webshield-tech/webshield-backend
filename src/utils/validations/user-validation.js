export async function signUpValidation(req, res, next) {
  const { email, password, username } = req.body;

  const emailRegex = /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,}@[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const validEmail = emailRegex.test(email);
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/;
  const validPassword = passwordRegex.test(password);
  const validUsername = username && username.length >= 3;

  if (validEmail && validPassword && validUsername) {
    next();
  } else {
    res.status(400).json({
      error: 'Invalid user data',
      details: {
        email: validEmail ? 'Valid' : 'Invalid email format',
        password: validPassword
          ? 'Valid'
          : 'Password must contain: 8+ characters, uppercase, lowercase, Number, Special character',
        username: validUsername ? 'Valid' : 'Username must be at least 3 characters',
      },
    });
  }
}

export async function loginValidation(req, res, next) {
  // Accept email, username, or emailOrUsername
  const identifier = req.body.emailOrUsername || req.body.email || req.body.username;
  const password = req.body.password;

  if (!identifier) {
    return res.status(400).json({
      success: false,
      error: 'Please fill the Fields',
    });
  }

  if (!password) {
    return res.status(400).json({
      success: false,
      error: 'Password is required',
    });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[! @#$%^&*()_+\-=\[\]{};':"\\|,. <>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/? ]{8,}$/;

  const validPassword = passwordRegex.test(password);

  if (validPassword) {
    next();
  } else {
    res.status(400).json({
      success: false,
      error: 'Invalid password format',
      details: 'Password must contain:  8+ chars, uppercase, lowercase, number, special character',
    });
  }
}
