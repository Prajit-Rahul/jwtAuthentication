import jwt from 'jsonwebtoken';
import { jwtTokens } from '../utils/jwt-helpers.js';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']; //Bearer TOKEN
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).json({error:"Null token"});
  console.log("Auth1 Done");
  console.log("token1: ", token);
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
    if (error) return res.status(403).json({error : error.message});
    //req.user = user;
    console.log("Auth2 Done");
    next();
  });
}

const renew = (req, res, next) =>{
    const refreshToken = req.cookies.refresh_token;
    console.log("RefreshToken: ",refreshToken);
    if(refreshToken == null) return res.sendStatus(401);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
      if (error) return res.status(403).json({error:error.message});
      // const accessToken = jwtTokens(user).accessToken;
      // console.log("Curr: ",accessToken)
      const accessToken = jwt.sign({name: user.name}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '20s'});
      console.log("Curr: ",accessToken)
      // res.setHeader('authorization', accessToken);
      req.headers.authorization = `Bearer ${accessToken}`;
    });
    console.log("ENsd");
    next();
}

export {authenticateToken, renew};