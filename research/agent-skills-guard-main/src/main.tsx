import React from "react";
import ReactDOM from "react-dom/client";
import "./i18n/config";
import App from "./App";
import "./styles/globals.css";
import { UpdateProvider } from "./contexts/UpdateContext";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <UpdateProvider>
      <App />
    </UpdateProvider>
  </React.StrictMode>
);
