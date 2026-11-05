class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.3.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "cc81c92fd6f5704f1bea24bb64fab2bceb40bbaa6ee598420b1d50b94d5e3f15"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "780f0c485388d162a77a5215b96c52979417d9b4a8b8a05a6e2de8f767f1a014"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7d3022f6426cd2b67a77c00c86ebd53bd9b1dcbbdd01ef0f157d10aac7bfc5de"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2e1543e2cf0f57e6882a2fd28022896d673386b38dff72af798b18d779332c7f"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
