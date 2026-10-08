import { NotificationBell } from "../components/NotificationBell";
import { UserMenu } from "../components/UserMenu";

export function TopBar() {
  return (
    <div className="flex items-center justify-end gap-1 border-b border-lm-line bg-lm-panel px-6 py-2.5 shrink-0">
      <NotificationBell />
      <UserMenu />
    </div>
  );
}
