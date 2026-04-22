import React from "react";
import { toast, type ExternalToast } from "sonner";

type ToastPosition = NonNullable<ExternalToast["position"]>;

export type AppToastOptions = Omit<ExternalToast, "position"> & {
  position?: ToastPosition;
};

type BannerTone = "info" | "success" | "error";

type AppToastBannerOptions = {
  duration?: number;
  tone?: BannerTone;
  position?: Extract<ToastPosition, "bottom-center" | "top-center" | "top-right">;
};

const DEFAULT_DURATION_MS = 3000;

const defaultCornerOptions: Pick<ExternalToast, "duration" | "position"> = {
  duration: DEFAULT_DURATION_MS,
  position: "top-right",
};

const bannerBaseClasses = [
  "w-[min(100vw-2rem,24rem)] px-5 py-4 text-sm text-left",
  "rounded-2xl border border-border/70 bg-card/70 text-foreground",
  "shadow-[0_6px_16px_rgba(0,0,0,0.12)] backdrop-blur-md",
].join(" ");

const toneClasses: Record<BannerTone, { icon: string }> = {
  info: { icon: "text-primary" },
  success: { icon: "text-success" },
  error: { icon: "text-destructive" },
};

export const appToast = {
  message(message: React.ReactNode, options?: AppToastOptions) {
    return toast.message(message, { ...defaultCornerOptions, ...options });
  },
  success(message: React.ReactNode, options?: AppToastOptions) {
    return toast.success(message, { ...defaultCornerOptions, ...options });
  },
  info(message: React.ReactNode, options?: AppToastOptions) {
    return toast.info(message, { ...defaultCornerOptions, ...options });
  },
  warning(message: React.ReactNode, options?: AppToastOptions) {
    return toast.warning(message, { ...defaultCornerOptions, ...options });
  },
  error(message: React.ReactNode, options?: AppToastOptions) {
    return toast.error(message, { ...defaultCornerOptions, ...options });
  },
  loading(message: React.ReactNode, options?: AppToastOptions) {
    return toast.loading(message, { ...defaultCornerOptions, ...options });
  },
  banner(message: React.ReactNode, options?: AppToastBannerOptions) {
    const duration = options?.duration ?? DEFAULT_DURATION_MS;
    const position = options?.position ?? "top-right";
    const tone: BannerTone = options?.tone ?? "info";

    return toast.custom(
      (id) =>
        React.createElement(
          "button",
          {
            type: "button",
            onClick: () => toast.dismiss(id),
            className: bannerBaseClasses,
          },
          React.createElement(
            "div",
            { className: "flex items-center" },
            React.createElement(
              "span",
              { className: `${toneClasses[tone].icon} mr-3 text-base` },
              "›"
            ),
            React.createElement("span", { className: "tracking-wide" }, message)
          )
        ),
      { duration, position }
    );
  },
};
