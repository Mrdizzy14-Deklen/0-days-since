import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";

export function DevAvatar({
  login,
  src,
  className,
}: {
  login: string;
  src: string | null | undefined;
  className?: string;
}) {
  return (
    <Avatar className={cn("size-8 bg-muted", className)}>
      {src && <AvatarImage src={src} alt="" />}
      <AvatarFallback className="text-[10px] font-medium uppercase">
        {login.slice(0, 2)}
      </AvatarFallback>
    </Avatar>
  );
}
