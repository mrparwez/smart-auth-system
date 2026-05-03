import { useState } from "react";
import axios from "axios";

export default function App() {
  const [isLogin, setIsLogin] = useState(true);

  const [form, setForm] = useState({
    "email": "",
    "username": "",
    "password": ""
  });

  const [response, setResponse] = useState("");

  const API = "https://musical-space-couscous-45x5xpqr5gvhjvg7-8000.app.github.dev/api";

  const handleSubmit = async () => {
    try {
      const url = isLogin ? `${API}/login/` : `${API}/register/`;

      const payload = isLogin
        ? { "email": form.email, "password": form.password }
        : form;

      const res = await axios.post(url, payload);

      setResponse(JSON.stringify(res.data, null, 2));
    } catch (err) {
  console.log("FULL ERROR:", err);
  console.log("RESPONSE:", err.response);

  setResponse(
    err.response?.data
      ? JSON.stringify(err.response.data, null, 2)
      : err.message
  );
}
  };

  return (
    <div style={{ padding: 40 }}>
      <h1>Smart Auth System</h1>

      <button onClick={() => setIsLogin(true)}>Login</button>
      <button onClick={() => setIsLogin(false)}>Register</button>

      <h2>{isLogin ? "LOGIN" : "REGISTER"}</h2>

      <input
        placeholder="Email"
        onChange={(e) => setForm({ ...form, email: e.target.value })}
      />

      {!isLogin && (
        <input
          placeholder="Username"
          onChange={(e) => setForm({ ...form, "username": e.target.value })}
        />
      )}

      <input
        type="password"
        placeholder="Password"
        onChange={(e) => setForm({ ...form, password: e.target.value })}
      />

      <br /><br />

      <button onClick={handleSubmit}>
        {isLogin ? "Login" : "Register"}
      </button>

      <pre>{response}</pre>
    </div>
  );
}