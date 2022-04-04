import Router from 'express';
import userController from '../controllers/userController.js';
import authHandler from '../middleware/authHandler.js'
import userHandler from '../middleware/userHandler.js';

const router = Router();

router.use((req, res, next) => {
    console.log('---> userRouter.js');
    next();
});
router.route('/profiledata')
    .post(userController.addProfileData)

router.route('/:username')
    .get(userController.loginUrl)

router.use(userHandler.validateUserEmail);

router.route('/user')
    .delete(userController.deactivate)
    .put(userController.reactivate)
    .post(userController.getFullUser)

router.route('/grants')
    .post(userController.grants)
    .delete(userController.delGrants)
    .put(userController.addGrants)


router.use(userHandler.validateUserPassword);

const addTimestamp = (req, res, next) => {
    console.log('---> userRouter:addTimestamp');
    req.body.timestamp = new Date();
    next();
}


router.route('/register')
    .post(authHandler.encryptPassword)
    .post(addTimestamp)
    .post(userController.register);

router.route('/login')
    .post(userController.login);

router.route('/newpass')
    .put(userController.newPass)



export default router;