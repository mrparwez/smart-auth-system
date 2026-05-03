import { useState } from "react";
import API from "../api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [data, setData] = useState(null);

  const handleLogin = async () => {
    try {
      const res = await API.post("login/", {
        email,
        password,
      });

      setData(res.data);

      localStorage.setItem("token", res.data.access_token);

    } catch (err) {
      alert("Login failed");
    }
  };

  return (
    <div style={{ padding: 40 }}>
      <h2>Login</h2>

      <input
        placeholder="Email"
        onChange={(e) => setEmail(e.target.value)}
      /><br/><br/>

      <input
        placeholder="Password"
        type="password"
        onChange={(e) => setPassword(e.target.value)}
      /><br/><br/>

      <button onClick={handleLogin}>Login</button>

      {data && (
        <div>
          <h3>Result:</h3>
          <p>Risk Score: {data.risk_score}</p>
          <p>Suspicious: {data.is_suspicious ? "Yes" : "No"}</p>
          <p>Flags: {data.flags.join(", ")}</p>
        </div>
      )}
    </div>
  );
}