import HttpError from "http-errors";
import userModel from '../models/usersModel.js'
import bcrypt from 'bcrypt';
import messageapp from '../data/messages.js';
import messageusr from '../models/user/messagesusr.js';

const register = (req, res, next) => {
	console.log(`---> userController::register`);

	try {
		const body = req.body;
		let result;

		if (!body.username || !body.password) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {


			console.log(`---> userController::register ${body.password}`);
			const user = { username: body.username, password: body.password, timestamp: (body.timestamp || 0), active: 1 };

			result = userModel.loginUser(user);
			if (result != undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));

			} else {

				result = userModel.createUser(user);

				if (result < 0)
					next(HttpError(400, { message: messageapp.user_error_register }))

				res.status(201).json(result);

			}

		}

	} catch (error) {
		next(error);
	}

};

const login = (req, res, next) => {
	console.log(`---> userController::login`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || !body.password || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, password: body.password, timestamp: (body.timestamp || 0) };
			const result = userModel.loginUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				let nosensitive = JSON.parse(JSON.stringify(result))

				delete nosensitive.password
				delete nosensitive.active
				nosensitive.notices=userModel.getNotices(nosensitive)
				console.log(`---> userController::login ${result.password}`);
				console.log(`---> userController::login ${body.password}`);
				console.log(`=================================`);
				console.log(`${nosensitive.notices}}`);
				console.log(`=================================`);

					nosensitive.message = messageusr.user_msg_login
					res.status(200).json(nosensitive);
			
			}
		}
	} catch (error) {
		next(error);
	}
};




const loginUrl = (req, res, next) => {
	console.log(`---> userController::Urlogin`);

	try {
		const body = req.params;
		const usr = userModel.checkActive(body)

		if (!body || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, password: body.password, timestamp: (body.timestamp || 0) };

			const result = userModel.loginUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				let nosensitive = JSON.parse(JSON.stringify(result))

				delete nosensitive.password
				delete nosensitive.active
				delete nosensitive.profiledata
				delete nosensitive.notices
				console.log(`---> userController::login ${result.password}`);
				console.log(`---> userController::login ${body.password}`);
				nosensitive.message = messageusr.user_msg_login

				res.status(200).json(nosensitive);
			}
		}

	} catch (error) {
		next(error);
	}
};




const grants = (req, res, next) => {
	console.log(`---> userController::grant`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, grants: (body.grants || 0) };
			const result = userModel.grantUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				const nopass = JSON.parse(JSON.stringify(result))
				delete nopass.password
				res.status(200).json(nopass);

			}
		}

	} catch (error) {
		next(error);
	}
};



const delGrants = (req, res, next) => {
	console.log(`---> userController::delgrant`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, grants: (body.grants || 0) };
			const result = userModel.delGrantUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				const nopass = JSON.parse(JSON.stringify(result))
				delete nopass.password
				res.status(200).json(nopass);

			}
		}

	} catch (error) {
		next(error);
	}
};


const addGrants = (req, res, next) => {
	console.log(`---> userController::addgrant`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, grants: (body.grants || 0) };
			const result = userModel.addGrantUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				const nopass = JSON.parse(JSON.stringify(result))
				delete nopass.password
				res.status(200).json(nopass);

			}
		}

	} catch (error) {
		next(error);
	}
};

const newPass = (req, res, next) => {
	console.log(`---> userController::newPass`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || !body.password || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {
			const user = { username: body.username, password: body.password, newpassword: body.newpassword };
			const oldpass = userModel.oldHash(user)
			user.password = bcrypt.hashSync(user.newpassword, 10);
			const result = userModel.newPass(user);
			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {

				console.log(`---> userController::login ${result.password}`);
				console.log(`---> userController::login ${body.password}`);

				if (!bcrypt.compareSync(body.password, oldpass))
					next(HttpError(400, { message: messageapp.user_error_login }));
				else {
					result.password = user.password
					res.status(200).json(result);
				}
			}
		}

	} catch (error) {
		next(error);
	}
};

const deactivate = (req, res, next) => {
	console.log(`---> userController::deactivate`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {
			const user = { username: body.username };
			const result = userModel.deactivate(user);
			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				res.status(200).json(result);

			}
		}

	} catch (error) {
		next(error);
	}
};
const reactivate = (req, res, next) => {
	console.log(`---> userController::reactivate`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 0) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {
			const user = { username: body.username };
			const result = userModel.reactivate(user);
			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {

				res.status(200).json(result);

			}
		}

	} catch (error) {
		next(error);
	}
};

const getFullUser = (req, res, next) => {
	console.log(`---> userController::getFullUser`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || !body.password || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {

			const user = { username: body.username, password: body.password, timestamp: (body.timestamp || 0) };
			const result = userModel.getFullUser(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				
				console.log(`---> userController::getFullUser ${result.password}`);
				console.log(`---> userController::getFullUser ${body.password}`);

				if (!bcrypt.compareSync(body.password, result.password))
					next(HttpError(400, { message: messageapp.user_error_login }));
				else {
					res.status(200).json(result);
				}
			}
		}
	} catch (error) {
		next(error);
	}
};

const addProfileData= (req, res, next) => {
	console.log(`---> userController::addProfileData`);

	try {
		const body = req.body;
		const usr = userModel.checkActive(body)

		if (!body.username || usr != 1) {
			next(HttpError(400, { message: messageapp.parameter_not_especified }))
		} else {
			const user = { username: body.username, password: body.password, timestamp: (body.timestamp || 0), profiledata: body.profiledata };
			const result = userModel.addProfileData(user);

			if (result === undefined) {
				next(HttpError(400, { message: messageapp.user_error_login }));
			} else {
				let nosensitive = JSON.parse(JSON.stringify(result))

				delete nosensitive.password
				delete nosensitive.active
				console.log(`---> userController::addProfileData ${result.password}`);
				console.log(`---> userController::addProfileData ${body.password}`);
				nosensitive.message = messageusr.user_msg_addprofiledata

				res.status(200).json(nosensitive);
			}
		}
	} catch (error) {
		next(error);
	}

}

export default {
	register,
	login,
	loginUrl,
	grants,
	delGrants,
	addGrants,
	newPass,
	deactivate,
	reactivate,
	getFullUser,
	addProfileData
}