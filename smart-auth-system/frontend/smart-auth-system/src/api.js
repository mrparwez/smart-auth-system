import axios from "axios";

const API = axios.create({
  baseURL: "https://musical-space-couscous-45x5xpqr5gvhjvg7-8000.app.github.dev/api/",
});

export default API;