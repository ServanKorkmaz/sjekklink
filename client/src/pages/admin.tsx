import { Header } from "@/components/header";
import { Footer } from "@/components/footer";
import { AdminDashboard } from "@/components/admin-dashboard";

export default function Admin() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Header />
      <main>
        <AdminDashboard />
      </main>
      <Footer />
    </div>
  );
}
