import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { RequireAuth } from "./auth/RequireAuth";
import { Shell } from "./layout/Shell";
import { AssetDetail } from "./pages/AssetDetail";
import { AttackPaths } from "./pages/AttackPaths";
import { Engagements } from "./pages/Engagements";
import { Findings } from "./pages/Findings";
import { Inventory } from "./pages/Inventory";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { Scans } from "./pages/Scans";

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="login" element={<Login />} />
          <Route
            element={
              <RequireAuth>
                <Shell />
              </RequireAuth>
            }
          >
            <Route index element={<Overview />} />
            <Route path="inventory" element={<Inventory />} />
            <Route path="inventory/:assetId" element={<AssetDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="scans" element={<Scans />} />
            <Route path="attack-paths" element={<AttackPaths />} />
            <Route path="engagements" element={<Engagements />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
