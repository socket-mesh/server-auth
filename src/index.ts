import jwt from 'jsonwebtoken';
import { InvalidArgumentsError } from '@socket-mesh/errors';

export interface AuthTokenOptions extends jwt.SignOptions {
	rejectOnFailedDelivery?: boolean;
}

export class AuthEngine {
	verifyToken(signedToken: string, key: jwt.Secret | jwt.GetPublicKeyOrSecret, options: jwt.VerifyOptions): Promise<jwt.JwtPayload> {
		const jwtOptions = Object.assign({}, options || {});

		if (typeof signedToken === 'string' || signedToken == null) {
			return new Promise((resolve, reject) => {
				const cb: jwt.VerifyCallback<jwt.JwtPayload> = (err, token) => {
					if (err) {
						reject(err);
						return;
					}
					resolve(token);
				};
				
				jwt.verify(signedToken || '', key, jwtOptions, cb); 
			});
		}

		return Promise.reject(
			new InvalidArgumentsError('Invalid token format - Token must be a string')
		);
	}

	signToken(token: string | object | Buffer, key: jwt.Secret, options: jwt.SignOptions): Promise<string> {
		const jwtOptions = Object.assign({}, options || {});

		return new Promise<string>((resolve, reject) => {
			jwt.sign(token, key, jwtOptions, (err, signedToken) => {
				if (err) {
					reject(err);
					return;
				}
				resolve(signedToken);
			});
		});
	}
}