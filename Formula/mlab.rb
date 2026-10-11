class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.2.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "19e2f004b376c1fcc42ea58ffee8aa869d26890703f3ede98739e011aeb892d9"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f27e33b94b5c7d13ae9667237104cfba481f7b0a4b69fb6f1818fce3b2738cf1"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4317b26ea301bd5ee27cca8ec13a63a7aa8ddf7fccbc6938a7021e20b998719b"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2d7430e395a68dbed0d61c483214abddb77bec82f60469c5da3cd65d23519014"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
