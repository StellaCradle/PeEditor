#include <Windows.h>
#include <cxxopts.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <pe_bliss/pe_bliss.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;

void pauseCMD(bool pause) {
  if (pause)
    system("pause");
}

int main(int argc, char **argv) {
  auto logger = spdlog::stdout_color_mt("StellaCradle");

  if (argc == 1) {
    SetConsoleCtrlHandler([](DWORD signal) -> BOOL { return TRUE; }, TRUE);
    EnableMenuItem(GetSystemMenu(GetConsoleWindow(), FALSE), SC_CLOSE,
                   MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
  }

  cxxopts::Options options("SCPeEditor", "Pe Editor For AIC");
  options.allow_unrecognised_options();
  options.add_options()(
      "exe", "Exe file name",
      cxxopts::value<std::string>()->default_value("AliceInCradle.exe"))(
      "dll", "Dll file name",
      cxxopts::value<std::string>()->default_value("StellaCradle.dll"))(
      "h,help", "Print usage");

  auto optionsResult = options.parse(argc, argv);

  if (optionsResult.count("help")) {
    logger->info(options.help());
    return 0;
  }

  std::string exeFile = optionsResult["exe"].as<std::string>();
  std::string dllFile = optionsResult["dll"].as<std::string>();

  std::ifstream originalExeFile(exeFile, std::ios::binary);
  if (!originalExeFile) {
    logger->error("Cannot open {}", exeFile);
    pauseCMD(true);
    return -1;
  }

  try {
    auto originalPe = std::make_unique<pe_bliss::pe_base>(
        pe_bliss::pe_factory::create_pe(originalExeFile));
    std::ofstream modifiedExeFile("AliceInStellaCradle.exe",
                                  std::ios::binary | std::ios::trunc);
    if (!modifiedExeFile) {
      logger->error("Cannot generate AliceInStellaCradle.exe");
      pauseCMD(true);
      return -1;
    }

    pe_bliss::imported_functions_list imports(
        get_imported_functions(*originalPe));
    pe_bliss::import_library preLoader;
    preLoader.set_name(dllFile);

    pe_bliss::imported_function func;
    func.set_name("imp_func");
    func.set_iat_va(0x1);
    preLoader.add_import(func);
    imports.push_back(preLoader);

    pe_bliss::section ImportSection;
    ImportSection.get_raw_data().resize(1);
    ImportSection.set_name("ImpFunc");
    ImportSection.readable(true).writeable(true);
    pe_bliss::section &attachedImportedSection =
        originalPe->add_section(ImportSection);

    rebuild_imports(*originalPe, imports, attachedImportedSection,
                    pe_bliss::import_rebuilder_settings(true, false));
    rebuild_pe(*originalPe, modifiedExeFile);

    modifiedExeFile.close();
    logger->info("Generated AliceStellaInCradle.exe successfully", exeFile);
  } catch (pe_bliss::pe_exception &e) {
    logger->error("Failed to generate AliceStellaInCradle.exe\n{}", e.what());
    fs::remove("AliceInStellaCradle.exe");
  } catch (...) {
    logger->error(
        "Failed to generate AliceStellaInCradle.exe with unknown error");
    fs::remove("AliceInStellaCradle.exe");
  }

  pauseCMD(true);
  return 0;
}
