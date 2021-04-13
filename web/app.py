from http import HTTPStatus
from config import api, app
from resources.register import Register
from resources.login import Login
from resources.password_change import PasswordChange
from resources.username_change import UsernameChange
from resources.refill import Refill
from resources.update_balance import UpdateBalance
from resources.check_balance import CheckBalance
from resources.transfer import Transfer
from resources.take_loan import TakeLoan
from resources.pay_loan import PayLoan


api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(PasswordChange, "/passwordchange")
api.add_resource(UsernameChange, "/usernamechange")
api.add_resource(Refill, "/refill")
api.add_resource(UpdateBalance, "/updatebalance")
api.add_resource(CheckBalance, "/checkbalance")
api.add_resource(Transfer, "/transfer")
api.add_resource(TakeLoan, "/takeloan")
api.add_resource(PayLoan, "/payloan")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
