const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { UserInputError } = require('apollo-server');

const { validateRegisterInput, validateLoginInput } = require('../../util/validators');
const { SECRET_KEY } = require('../../config');
const User = require('../../models/User');

function generateToken(user) {
    return jwt.sign({
        id: user.id,
        email: user.email,
        username: user.username
    }, SECRET_KEY, { expiresIn: '1h' });
};

module.exports = {
    Mutation: {
        async login(_, { username, password }) {
            const { errors, valid } = validateLoginInput(username, password);

            if (!valid) {
                throw new UserInputError('Errors', { errors });
            }

            const user = await User.findOne({ username }); //check base if user exists

            if (!user) {
                errors.general = 'User not found';
                throw new UserInputError('User not found', { errors });
            }

            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                errors.general = 'Wrong credentials';
                throw new UserInputError('Wrong credentials', { errors });
            }

            const token = generateToken(user);

            return {
                ...user._doc,
                id: user._id,
                token
            }
        },

        async register(_, { registerInput: { username, email, password, confirmPassword } }, context, info) {
            // TODO: validate user data
            const { valid, errors } = validateRegisterInput(username, email, password, confirmPassword);
            if (!valid) {
                throw new UserInputError('Errors', { errors });
            }


            // TODO: make sure user doesn't already exists

            const user = await User.findOne({ username });

            // check if username already exists in database, if yes throw error from apollo-server and this second map is used for frontend
            if (user) {
                throw new UserInputError('Username is taken', {
                    errors: {
                        username: 'This username is taken'
                    }
                })
            }

            // hash password and create auth token
            password = await bcrypt.hash(password, 12); // hash password before save to database, btw bcrypt.hash is async so we need await and async before register function

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            }); // create new User object

            const res = await newUser.save();

            // get token for user
            const token = generateToken(res);

            return {
                ...res._doc,
                id: res._id,
                token
            }

        }
    }
};