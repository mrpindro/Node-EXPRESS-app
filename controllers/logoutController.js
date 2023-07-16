const User = require('../model/User');

const handleLogout = async (req, res) => {
    // On client, also delete the access token

    const cookies = req.cookies;

    if(!cookies?.jwt) {
        return res.sendStatus(204); // No content
    }
    const refreshToken = cookies.jwt;

    // is refresh token in database?
    const foundUser = await User.findOne({ refreshToken }).exec();
    if (!foundUser) {
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        return res.status(204); // no content
    }

    // Delete refresh token in db
    foundUser.refreshToken = '';
    const result = await foundUser.save();
    console.log(result);

    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
    res.sendStatus(204) // no content
}

module.exports = { handleLogout }