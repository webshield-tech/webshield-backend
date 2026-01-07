import express from 'express';
import { forgotPassword, resetPassword } from '../controllers/auth-controller.js';

const authRouter = express.Router();

authRouter.post('/forgot-password', forgotPassword);
authRouter.post('/reset-password', resetPassword);

export default authRouter;
