import { Outlet } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { TopBar } from "./TopBar";

export function Shell() {
  return (
    <div className="flex h-screen w-screen bg-lm-bg text-lm-text font-ui overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <div className="flex-1 overflow-y-auto">
          <div className="max-w-[1400px] mx-auto p-8">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
