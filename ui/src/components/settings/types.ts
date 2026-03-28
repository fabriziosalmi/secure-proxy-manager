export interface SettingsSectionProps {
  formData: Record<string, string>;
  onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => void;
  onToggle: (name: string, value: boolean) => void;
}
