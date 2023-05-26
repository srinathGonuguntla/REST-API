import express from 'express';
import { merge, get } from 'lodash';

import { getUserBySessionToken } from '../db/users'; 

//fisrt middleware
export const isAuthenticated = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const sessionToken = req.cookies['ANTONIO-AUTH'];//controllers=>authentication->login
  
      if (!sessionToken) {
        return res.sendStatus(403);
      }
  
      const existingUser = await getUserBySessionToken(sessionToken);
  
      if (!existingUser) {
        return res.sendStatus(403);
      }
  
      merge(req, { identity: existingUser });//request object line-7-next
  
      return next();
    } catch (error) {
      console.log(error);
      return res.sendStatus(400);
    }
  }

  //another middleware (owner)
  export const isOwner = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const { id } = req.params;
      const currentUserId = get(req, 'identity._id') as string;
  
      if (!currentUserId) {
        return res.sendStatus(400);
      }
  
      if (currentUserId.toString() !== id) {
        return res.sendStatus(403);
      }
  
      next();
    } catch (error) {
      console.log(error);
      return res.sendStatus(400);
    }
  }