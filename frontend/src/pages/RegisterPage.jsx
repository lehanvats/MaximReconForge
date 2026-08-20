import { Link } from "react-router-dom";

function RegisterPage() {
  return (
    <section className="flex min-h-screen items-center justify-center px-6 pt-[100px] pb-16">
      <div className="w-[400px] max-w-full rounded-[22px] border border-white/8 bg-[rgba(15,19,40,0.72)] p-9 backdrop-blur-[18px]">
        <h1 className="text-[26px] font-extrabold tracking-[-1px]">Registration closed</h1>
        <p className="mt-2 text-[14px] text-[#a7aec8]">
          This is a private deployment.
        </p>

        <div className="mt-7 flex flex-col gap-4">
          <button
            type="button"
            disabled
            aria-disabled="true"
            className="rounded-full bg-white/10 px-5 py-3 text-[14px] font-bold text-white/50 cursor-not-allowed"
          >
            No new registrations possible
          </button>
        </div>

        <p className="mt-6 text-center text-[13px] text-[#a7aec8]">
          Already have an account?{" "}
          <Link to="/login" className="font-semibold text-[#7c5cff] hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </section>
  );
}

export default RegisterPage;
