import express from 'express';
import jwt from 'jsonwebtoken';
import pool from '../db.js';
import bcrypt from 'bcrypt';
import { jwtTokens } from '../utils/jwt-helpers.js';
import {authenticateToken, checkAuthenticated, checkNotAuthenticated ,renewAccessToken, attachAccessToken, renew} from '../middleware/authorization.js';

const router = express.Router();

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (users.rows.length === 0) return res.status(401).json({error:"Email is incorrect"});
    //PASSWORD CHECK
    const validPassword = await bcrypt.compare(password, users.rows[0].password);
    if (!validPassword) return res.status(401).json({error: "Incorrect password"});
    //JWT
    let tokens = jwtTokens(users.rows[0]);//Gets access and refresh tokens
    res.cookie('refresh_token', tokens.refreshToken, {...(process.env.COOKIE_DOMAIN && {domain: process.env.COOKIE_DOMAIN}) , httpOnly: true,sameSite: 'none'});
    res.json(tokens);
    //res.render('dashboard');
    //res.redirect("/api/auth/dashboard");
    // return res.redirect("/api/auth/dashboard");
  } catch (error) {
    res.status(401).json({error: error.message});
  } 
});

router.get("/dashboard", renew ,authenticateToken,(req, res) => {
  res.render("dashboard");
})

router.get('/refresh_token', (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    if (refreshToken === null) return res.sendStatus(401);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
      if (error) return res.status(403).json({error:error.message});
      let tokens = jwtTokens(user);
      res.cookie('refresh_token', tokens.refreshToken, {...(process.env.COOKIE_DOMAIN && {domain: process.env.COOKIE_DOMAIN}) , httpOnly: true,sameSite: 'none'});
      return res.json(tokens);
    });
  } catch (error) {
    res.status(401).json({error: error.message});
  }
});

router.get('/token', (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if(refreshToken == null) return res.sendStatus(401);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
    if (error) return res.status(403).json({error:error.message});
    const accessToken = jwt.sign({name: user.name}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '20s'});
    res.setHeader('Authorization', accessToken);
    res.json({accessToken: accessToken});
  });
})

router.delete('/refresh_token', (req, res) => {
  try {
    res.clearCookie('refresh_token');
    return res.status(200).json({message:'Refresh token deleted.'});
  } catch (error) {
    res.status(401).json({error: error.message});
  }
});

export default router;
