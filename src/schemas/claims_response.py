class ClaimsResponse:
    """
    Represents a claims response with various attributes.
    """
    def __init__(self, iss, aud, exp, tid, kid, alg, iat=None, nbf=None, sub=None, name=None, email=None):
        self.iss = iss
        self.aud = aud
        self.exp = exp
        self.tid = tid
        self.kid = kid
        self.alg = alg
        self.iat = iat
        self.nbf = nbf
        self.sub = sub
        self.name = name
        self.email = email

    def jsonify(self) -> dict:
        """
        Converts the claims response to a JSON serializable dictionary.

        Returns:
            dict: A dictionary representation of the claims response.
        """
        return dict(self.__dict__)