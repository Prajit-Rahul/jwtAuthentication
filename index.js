import express, {json} from 'express';
import cors from 'cors';
import usersRouter from './routes/users-routes.js';
import authRouter from './routes/auth-routes.js';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import { dirname,join } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from "module";
import { checkAuthenticated } from './middleware/authorization.js';
// const require = createRequire(import.meta.url);

// const flash = require('express-flash');

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 5000;
const corsOptions = {credentials:true, origin: process.env.URL || '*'};

app.set('view engine', "ejs")
app.use(express.urlencoded({extended: false}));
// app.use(flash());

app.use(cookieParser());

app.use(cors(corsOptions));
app.use(json());

app.use('/', express.static(join(__dirname, 'public')))



app.use('/api/auth',authRouter);
app.use('/api/users', usersRouter);

app.get('/', (req, res)=>{
  res.render('index');
})

app.get('/users/register', (req,res)=>{
  res.render("register");
})

app.get('/users/login', (req, res) => {
  res.render("login");
})


app.listen(PORT, ()=> {
  console.log(`Server is listening on port:${PORT}`);
})