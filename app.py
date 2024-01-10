from flask import Flask, render_template, request
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkiam.v3.region.iam_region import IamRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkiam.v3 import IamClient, KeystoneCreateUserTokenByPasswordRequest, PwdPasswordUserDomain, PwdPasswordUser, PwdPassword, PwdIdentity, PwdAuth, KeystoneCreateUserTokenByPasswordRequestBody

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get form data
        ak = request.form['ak']
        sk = request.form['sk']
        username = request.form['username']
        iam_username = request.form['iam_username']
        password = request.form['password']
        region = request.form['region']

        # Authenticate and get token
        try:
            credentials = GlobalCredentials(ak, sk)

            client = IamClient.new_builder() \
                .with_credentials(credentials) \
                .with_region(IamRegion.value_of(region)) \
                .build()

            request_data = KeystoneCreateUserTokenByPasswordRequest()
            domain_user = PwdPasswordUserDomain(name=username)
            user_password = PwdPasswordUser(domain=domain_user, name=iam_username, password=password)
            password_identity = PwdPassword(user=user_password)
            list_methods_identity = ["password"]
            identity_auth = PwdIdentity(methods=list_methods_identity, password=password_identity)
            auth_body = PwdAuth(identity=identity_auth)
            request_data.body = KeystoneCreateUserTokenByPasswordRequestBody(auth=auth_body)

            response = client.keystone_create_user_token_by_password(request_data)
            token = response.x_subject_token
            return render_template('result.html', token=token)

        except exceptions.ClientRequestException as e:
            error_msg = f"Error: {e.status_code} - {e.error_msg}"
            return render_template('index.html', error_msg=error_msg)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
