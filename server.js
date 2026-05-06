require('dotenv').config();
const mongoose = require('mongoose');
const app = require('./app');

// Import models
const User = require('./models/users');

const PORT = process.env.PORT || 3000;

// Connect to Atlas using Mongoose
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to RouteRelief database');
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((err) => console.log('Connection error', err));