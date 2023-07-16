require('dotenv').config();

const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const verifyJWT = require('./middleware/verifyJWT');
const corsOptions = require('./config/corsOptions');
const { logger } = require('./middleware/logEvents');
const errorHandler = require('./middleware/errorHandler');
const cookieParser = require('cookie-parser');
const credentials = require('./middleware/credentials');
const mongoose = require('mongoose');
const connectDB = require('./config/dbConn');

// Connect to MongoDB
connectDB();

// creating a PORT for our server 
const PORT = process.env.PORT || 3500;

// custom middleware logger
app.use(logger);

// Handle options credentials check - before CORS! 
// and fetch cookies credentials requirement
app.use(credentials);

// Cross Origin Resource Sharing
app.use(cors(corsOptions));

// built-in middleware to handle urlencoded data, in other words, form data. 
// 'content-type: application/x-www-form-urlencoded' 
app.use(express.urlencoded({ extended: false }));

// built-in middleware for json
app.use(express.json());

// middleware for cookies
app.use(cookieParser());

// serve static files 
app.use('/', express.static(path.join(__dirname, '/public')));
// app.use('/subdir', express.static(path.join(__dirname, '/public')));

// routes
app.use('/', require('./routes/root'));
app.use('/register', require('./routes/register'));
app.use('/auth', require('./routes/auth'));
app.use('/refresh', require('./routes/refresh'));
app.use('/logout', require('./routes/logout'));

app.use(verifyJWT);
app.use('/employees', require('./routes/api/employees'));

app.all('*', (req, res) => {
    res.status(404)
    if (req.accepts('html')) {
        res.sendFile(path.join(__dirname, 'views', '404.html'));
    } 
    else if (req.accepts('json')) {
        res.json({ error: "404 Not Found"});
    } else {
        res.type('txt').send("404 Not Found");
    }
})

// Error handler 
app.use(errorHandler);

// now launching our server with listen 
mongoose.connection.once('open', () => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
