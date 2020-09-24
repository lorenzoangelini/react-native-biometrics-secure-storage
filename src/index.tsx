import { NativeModules } from 'react-native';

type BiometricsSecureStorageType = {
  multiply(a: number, b: number): Promise<number>;
};

const { BiometricsSecureStorage } = NativeModules;

export default BiometricsSecureStorage as BiometricsSecureStorageType;
