const bcrypt = require('bcrypt');

// La contraseña que quieres encriptar
const password = '12345678';

bcrypt.hash(password, 10, (err, hash) => {
  if (err) {
    console.error(err);
  } else {
    console.log('Hash de la contraseña:', hash);
  }
});
