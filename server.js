// backend/server.js
const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();

app.use(cors({
  origin: 'http://localhost:3000', // Asume que tu frontend está en el puerto 3000
  credentials: true
}));
app.use(express.json());

// Configurar Sequelize
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASS, {
  host: process.env.DB_HOST,
  dialect: 'mysql'
});

// Definir modelos
const RegistrationCode = sequelize.define('RegistrationCode', {
  code: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: {
      msg: 'Este código ya está en uso'
    }
  },
  isUsed: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

const Parent = sequelize.define('Parent', {
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: {
        msg: 'El nombre no puede estar vacío'
      }
    }
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: {
        msg: 'El apellido no puede estar vacío'
      }
    }
  },
  documentNumber: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: {
      msg: 'Este número de documento ya está registrado'
    },
    validate: {
      notEmpty: {
        msg: 'El número de documento no puede estar vacío'
      }
    }
  },
  phoneNumber: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: {
        msg: 'El número de teléfono no puede estar vacío'
      }
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: {
      msg: 'Este correo electrónico ya está registrado'
    },
    validate: {
      isEmail: {
        msg: 'Por favor, introduce un correo electrónico válido'
      },
      notEmpty: {
        msg: 'El correo electrónico no puede estar vacío'
      }
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: {
        args: [6, 100],
        msg: 'La contraseña debe tener al menos 6 caracteres'
      }
    }
  },
  isEmailVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

const Child = sequelize.define('Child', {
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: {
        msg: 'El nombre no puede estar vacío'
      }
    }
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: {
        msg: 'El apellido no puede estar vacío'
      }
    }
  },
  age: {
    type: DataTypes.INTEGER,
    allowNull: false,
    validate: {
      isInt: {
        msg: 'La edad debe ser un número entero'
      },
      min: {
        args: [0],
        msg: 'La edad no puede ser negativa'
      },
      max: {
        args: [18],
        msg: 'La edad no puede ser mayor a 18 años'
      }
    }
  },
  documentNumber: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: {
      msg: 'Este número de documento ya está registrado'
    },
    validate: {
      notEmpty: {
        msg: 'El número de documento no puede estar vacío'
      }
    }
  }
});

Parent.hasMany(Child);
Child.belongsTo(Parent);

// Sincronizar modelos con la base de datos
sequelize.sync()
  .then(() => console.log('Base de datos sincronizada'))
  .catch(err => console.error('Error al sincronizar la base de datos', err));

    sequelize.authenticate()
    .then(() => console.log('Conexión a la base de datos establecida correctamente.'))
    .catch(err => console.error('No se pudo conectar a la base de datos:', err));

// Configurar nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Rutas

// Ruta para verificar el código
app.post('/verify-code', async (req, res) => {
  try {
    const { code } = req.body;
    const registrationCode = await RegistrationCode.findOne({ where: { code, isUsed: false } });
    if (registrationCode) {
      res.json({ success: true, message: 'Código válido' });
    } else {
      res.status(400).json({ success: false, message: 'Código inválido o ya utilizado' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error en el servidor' });
  }
});

// Ruta para registrar usuario
app.post('/register', async (req, res) => {
  try {
    const { parentData, childData, code } = req.body;

    // Verificar si el código de registro es válido y no se ha usado
    const registrationCode = await RegistrationCode.findOne({ where: { code, isUsed: false } });
    if (!registrationCode) {
      return res.status(400).json({ message: 'Código inválido o ya utilizado' });
    }

    // Crear el padre (encriptando la contraseña)
    const hashedPassword = await bcrypt.hash(parentData.password, 10);
    const parent = await Parent.create({
      ...parentData,
      password: hashedPassword,
    });

    // Crear el niño asociado al padre
    await Child.create({
      ...childData,
      parentId: parent.id,
    });

    // Marcar el código de registro como usado
    await registrationCode.update({ isUsed: true });

    const token = jwt.sign(
      { id: parent.id, email: parent.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    // Enviar correo de verificación al padre
    const verificationToken = jwt.sign({ email: parent.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    const verificationUrl = `http://tudominio.com/verify-email/${verificationToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: parent.email,
      subject: 'Verifica tu correo electrónico',
      html: `Por favor, verifica tu correo electrónico haciendo clic <a href="${verificationUrl}">aquí</a>.`,
    });

    res.status(201).json({
      message: 'Registro exitoso. Por favor, verifica tu correo electrónico.',
      token,
      user: {
        id: parent.id,
        email: parent.email,
        firstName: parent.firstName,
        lastName: parent.lastName
      }
    });
  } catch (error) {
    console.error(error);
    if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') {
      // Manejar errores de validación
      const validationErrors = error.errors.map(err => ({
        field: err.path,
        message: err.message
      }));
      return res.status(400).json({ message: 'Error de validación', errors: validationErrors });
    }
    res.status(500).json({ message: 'Error en el servidor' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { documentNumber, password } = req.body;
    const parent = await Parent.findOne({ where: { documentNumber } });
    if (!parent) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    const isMatch = await bcrypt.compare(password, parent.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    if (!parent.isEmailVerified) {
      return res.status(400).json({ message: 'Por favor, verifica tu correo electrónico antes de iniciar sesión' });
    }
    const token = jwt.sign({ userId: parent.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const parent = await Parent.findOne({ where: { email: decoded.email } });
    if (!parent) {
      return res.status(400).json({ message: 'Token inválido' });
    }
    await parent.update({ isEmailVerified: true });
    res.json({ message: 'Correo electrónico verificado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error en la verificación del correo electrónico' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));