class Escutcheon < Formula
  desc "Port knocking without the C daemon — Rust-native knockd replacement"
  homepage "https://github.com/tstapler/escutcheon"
  url "https://github.com/tstapler/escutcheon/archive/refs/tags/v#{version}.tar.gz"
  # sha256 updated by release workflow
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/tstapler/escutcheon.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
    # cargo install puts both binaries into #{prefix}/bin
  end

  test do
    assert_match "knock-ssh", shell_output("#{bin}/knock-ssh --help")
    assert_match "knock-sshd", shell_output("#{bin}/knock-sshd --help")
  end
end
